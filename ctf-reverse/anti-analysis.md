# CTF Reverse - Anti-Analysis Techniques & Bypasses

CTF 中常见的反调试、反 VM、反 DBI 与完整性校验技术及其实用绕过方法总览。

## Table of Contents
- [Linux Anti-Debug (Advanced)](#linux-anti-debug-advanced)
  - [ptrace-Based](#ptrace-based)
  - [/proc Filesystem Checks](#proc-filesystem-checks)
  - [Timing-Based Detection](#timing-based-detection)
  - [Signal-Based Anti-Debug](#signal-based-anti-debug)
  - [Syscall-Level Evasion](#syscall-level-evasion)
  - [Trap-Flag Self-Check with cmovz Patcher (Hack.lu 2018)](#trap-flag-self-check-with-cmovz-patcher-hacklu-2018)
  - [SIGFPE Handler for mprotect Code Mutation (Hack.lu 2018)](#sigfpe-handler-for-mprotect-code-mutation-hacklu-2018)
- [Windows Anti-Debug (Advanced)](#windows-anti-debug-advanced)
  - [PEB (Process Environment Block) Checks](#peb-process-environment-block-checks)
  - [NtQueryInformationProcess](#ntqueryinformationprocess)
  - [Heap Flags](#heap-flags)
  - [TLS Callbacks](#tls-callbacks)
  - [Hardware Breakpoint Detection](#hardware-breakpoint-detection)
  - [Software Breakpoint Detection (INT3 Scanning)](#software-breakpoint-detection-int3-scanning)
  - [Exception-Based Anti-Debug](#exception-based-anti-debug)
  - [NtSetInformationThread (Thread Hiding)](#ntsetinformationthread-thread-hiding)
- [Anti-VM / Anti-Sandbox](#anti-vm--anti-sandbox)
  - [CPUID Hypervisor Bit](#cpuid-hypervisor-bit)
  - [MAC Address / Hardware Fingerprinting](#mac-address--hardware-fingerprinting)
  - [Timing-Based VM Detection](#timing-based-vm-detection)
  - [File / Registry Artifacts](#file--registry-artifacts)
  - [Resource Checks (CPU Count, RAM, Disk)](#resource-checks-cpu-count-ram-disk)
- [Anti-DBI (Dynamic Binary Instrumentation)](#anti-dbi-dynamic-binary-instrumentation)
  - [Frida Detection](#frida-detection)
  - [Pin/DynamoRIO Detection](#pindynamorio-detection)
- [Code Integrity / Self-Hashing](#code-integrity--self-hashing)
- [Anti-Disassembly Techniques](#anti-disassembly-techniques)
  - [Opaque Predicates](#opaque-predicates)
  - [Junk Bytes / Overlapping Instructions](#junk-bytes--overlapping-instructions)
  - [Jump-in-the-Middle](#jump-in-the-middle)
  - [Function Chunking / Scattered Code](#function-chunking--scattered-code)
  - [Control Flow Flattening (Advanced)](#control-flow-flattening-advanced)
  - [Mixed Boolean-Arithmetic (MBA) Identification & Simplification](#mixed-boolean-arithmetic-mba-identification--simplification)
- [Comprehensive Bypass Strategies](#comprehensive-bypass-strategies)

CTF writeup 技巧（SIGILL handler、SIGFPE strace 侧信道、指令轨迹逆推、无 call 函数链、父进程修补子进程二进制导出）见 [anti-analysis-ctf.md](anti-analysis-ctf.md)。
  - [Universal Bypass Checklist](#universal-bypass-checklist)
  - [Layered Anti-Debug (Real-World Pattern)](#layered-anti-debug-real-world-pattern)
  - [Quick Reference: Check to Bypass](#quick-reference-check-to-bypass)

---

## Linux Anti-Debug (Advanced)

### ptrace-Based

**Self-ptrace（最常见）：**
```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) exit(1); // Already traced = debugger attached
```

**绕过：**
```bash
# 1. LD_PRELOAD（完整 hook 见 patterns.md）
LD_PRELOAD=./hook.so ./binary

# 2. 用 pwntools 打补丁
python3 -c "
from pwn import *
elf = ELF('./binary', checksec=False)
elf.asm(elf.symbols.ptrace, 'xor eax, eax; ret')
elf.save('patched')
"

# 3. GDB: 截 syscall
gdb ./binary
(gdb) catch syscall ptrace
(gdb) run
# When it stops at ptrace:
(gdb) set $rax = 0
(gdb) continue

# 4. 内核配置（需要 root）
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

**Double-ptrace 模式：**
```c
// Fork child to ptrace parent — blocks all other debuggers
pid_t child = fork();
if (child == 0) {
    ptrace(PTRACE_ATTACH, getppid(), 0, 0);
    // Child sits in waitpid loop, keeping parent traced
} else {
    // Parent continues with real logic
}
```
**绕过：** 杀掉 watchdog 子进程，再附加调试器。

### /proc Filesystem Checks

```c
// TracerPid check
FILE *f = fopen("/proc/self/status", "r");
// Looks for "TracerPid:\t0" — non-zero means debugger

// /proc/self/exe link check (some debuggers change this)
readlink("/proc/self/exe", buf, sizeof(buf));

// /proc/self/maps — check for debugger libraries
grep("frida", "/proc/self/maps");
```

**绕过：**
```bash
# 1. LD_PRELOAD hook fopen/fread 伪造 /proc 内容
# 2. 挂载命名空间隔离
unshare -m bash -c 'mount --bind /dev/null /proc/self/status && ./binary'

# 3. GDB: 在 fopen 处下断，改文件名参数
(gdb) b fopen
(gdb) run
(gdb) set {char[20]} $rdi = "/dev/null"
(gdb) continue
```

### Timing-Based Detection

```c
// rdtsc (CPU timestamp counter)
uint64_t start = __rdtsc();
// ... code ...
uint64_t delta = __rdtsc() - start;
if (delta > THRESHOLD) exit(1);  // too slow = debugger

// clock_gettime
struct timespec ts1, ts2;
clock_gettime(CLOCK_MONOTONIC, &ts1);
// ... code ...
clock_gettime(CLOCK_MONOTONIC, &ts2);

// gettimeofday
struct timeval tv1, tv2;
gettimeofday(&tv1, NULL);
```

**绕过：**
```bash
# 1. Frida hook（clock_gettime hook 见 tools-dynamic.md）

# 2. GDB: 用常量替代 rdtsc
(gdb) set {unsigned char[2]} 0x401234 = {0x90, 0x90}  # NOP the rdtsc

# 3. 用 Pin 工具固定 TSC 读取
# 4. faketime 库
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2024-01-01" ./binary
```

### Signal-Based Anti-Debug

```c
// SIGTRAP handler — INT3 under debugger is caught by debugger, not handler
signal(SIGTRAP, handler);
__asm__("int3");
// If handler runs: no debugger. If debugger catches: debugged.

// SIGALRM timeout — kill self if analysis takes too long
signal(SIGALRM, kill_handler);
alarm(5);

// SIGSEGV handler that does real work (see patterns.md for MBA pattern)
signal(SIGSEGV, real_logic_handler);
*(int*)0 = 0;  // deliberate crash → handler runs real code
```

**绕过：**
```bash
# GDB: 把信号交给程序而不是调试器处理
(gdb) handle SIGTRAP nostop pass
(gdb) handle SIGALRM ignore
(gdb) handle SIGSEGV nostop pass

# 对基于 alarm 的检查，可 patch alarm() 让其立即返回
```

### Syscall-Level Evasion

```c
// Direct syscall instead of libc — bypasses LD_PRELOAD hooks
long ret;
asm volatile("syscall" : "=a"(ret) : "a"(101), "D"(0), "S"(0), "d"(0), "r"(0));
// Syscall 101 = ptrace on x86_64
```

**绕过：** 必须直接 patch 二进制，或用 ptrace 在 syscall 层拦截。
```bash
# GDB: catch syscall
(gdb) catch syscall 101
(gdb) commands
> set $rax = 0
> continue
> end
```

---

## Windows Anti-Debug (Advanced)

### PEB (Process Environment Block) Checks

```c
// BeingDebugged flag (offset 0x2 in PEB)
bool debugged = NtCurrentPeb()->BeingDebugged;

// NtGlobalFlag (offset 0x68/0xBC in PEB)
// When debugger: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS = 0x70
DWORD flags = *(DWORD*)((BYTE*)NtCurrentPeb() + 0xBC); // 64-bit offset
if (flags & 0x70) exit(1);
```

**Bypass (x64dbg):**
```text
# ScyllaHide plugin auto-patches PEB fields
# Manual: dump PEB, zero BeingDebugged and NtGlobalFlag
```

### NtQueryInformationProcess

```c
// ProcessDebugPort (0x7)
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) exit(1);

// ProcessDebugObjectHandle (0x1E)
HANDLE debugObj = NULL;
NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), NULL);
if (status == 0) exit(1); // STATUS_SUCCESS means debugger present

// ProcessDebugFlags (0x1F) — returns inverse: 0 = debugger present
DWORD noDebug = 0;
NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &noDebug, sizeof(noDebug), NULL);
if (noDebug == 0) exit(1);
```

**绕过：** hook `NtQueryInformationProcess` 返回伪值，或直接使用 ScyllaHide。

### Heap Flags

```c
// Process heap has debug flags when debugger attached
PHEAP heap = (PHEAP)GetProcessHeap();
// Flags at offset 0x70 (64-bit): should be HEAP_GROWABLE (0x2)
// ForceFlags at offset 0x74: should be 0
if (heap->Flags != 0x2 || heap->ForceFlags != 0) exit(1);
```

### TLS Callbacks

**关键技术：** TLS（Thread Local Storage）回调会在 `main()` / entry point 之前执行。

```c
// Registered in PE header's TLS directory
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            ExitProcess(1);  // Kills process before main runs
        }
    }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK callbacks[] = { TlsCallback, NULL };
```

**在 IDA/Ghidra 中的检测：** 查看 PE TLS Directory → AddressOfCallBacks。列在其中的函数都会在 EP 前执行。

**绕过：** 在 x64dbg 里对 TLS callback 下断（Options → Events → TLS Callbacks），或直接 patch TLS 目录项。

### Hardware Breakpoint Detection

```c
// Read debug registers via GetThreadContext
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) exit(1);

// Also via exception handler: deliberate exception, check DR regs in handler
```

**绕过：**
```bash
# x64dbg: 改用软件断点，或 hook GetThreadContext
# Frida: hook GetThreadContext 并清零 DR 寄存器
```

### Software Breakpoint Detection (INT3 Scanning)

```c
// CRC / hash check over code section
unsigned char *code = (unsigned char*)function_addr;
uint32_t checksum = 0;
for (int i = 0; i < code_size; i++) {
    checksum += code[i];
    if (code[i] == 0xCC) exit(1);  // INT3 = software breakpoint
}
if (checksum != EXPECTED_CHECKSUM) exit(1);
```

**绕过：** 使用硬件断点（DR0-DR3）而不是软件断点，或 hook 扫描函数。

### Exception-Based Anti-Debug

```c
// UnhandledExceptionFilter — under debugger, filter is NOT called
SetUnhandledExceptionFilter(handler);
RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
// If handler runs: no debugger
// If debugger catches: debugger present

// INT 2D — debugger single-step anomaly
__asm { int 2dh }  // Debugger silently consumes the exception
// If execution continues: debugger present
```

### NtSetInformationThread (Thread Hiding)

```c
// Hide thread from debugger — stops all debug events
typedef NTSTATUS(NTAPI *pNtSIT)(HANDLE, ULONG, PVOID, ULONG);
pNtSIT NtSIT = (pNtSIT)GetProcAddress(GetModuleHandle("ntdll"), "NtSetInformationThread");
NtSIT(GetCurrentThread(), 0x11 /*ThreadHideFromDebugger*/, NULL, 0);
// After this, debugger won't see breakpoints or exceptions from this thread
```

**绕过：** hook `NtSetInformationThread` 忽略 class 0x11，或直接 patch 调用。

---

## Anti-VM / Anti-Sandbox

### CPUID Hypervisor Bit

```c
int regs[4];
__cpuid(regs, 1);
if (regs[2] & (1 << 31)) {  // ECX bit 31 = hypervisor present
    exit(1);
}

// Hypervisor brand string
__cpuid(regs, 0x40000000);
char brand[13] = {0};
memcpy(brand, &regs[1], 12);
// "VMwareVMware", "Microsoft Hv", "KVMKVMKVM", "XenVMMXenVMM"
```

**绕过：** patch `cpuid` 结果，或用 `LD_PRELOAD` hook 封装函数。

### MAC Address / Hardware Fingerprinting

```text
Known VM MAC prefixes:
  VMware:     00:0C:29, 00:50:56
  VirtualBox: 08:00:27
  Hyper-V:    00:15:5D
  Parallels:  00:1C:42
  QEMU:       52:54:00
```

### Timing-Based VM Detection

```c
// VM exits on privileged instructions are measurably slower
uint64_t start = __rdtsc();
__cpuid(regs, 0);  // Forces VM exit
uint64_t delta = __rdtsc() - start;
if (delta > 500) { /* likely VM */ }
```

### File / Registry Artifacts

```text
Files: C:\Windows\System32\drivers\vm*.sys, vbox*.dll, VBoxService.exe
Registry: HKLM\SOFTWARE\VMware, Inc.\VMware Tools
Services: VMTools, VBoxService
Processes: vmtoolsd.exe, VBoxTray.exe, qemu-ga.exe
Linux: /sys/class/dmi/id/product_name contains "VirtualBox"|"VMware"
       dmesg | grep -i "hypervisor detected"
```

### Resource Checks (CPU Count, RAM, Disk)

```c
// Sandboxes typically have minimal resources
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(1);

MEMORYSTATUSEX ms;
ms.dwLength = sizeof(ms);
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) exit(1); // < 2GB RAM

// Disk size check (< 60GB = sandbox)
GetDiskFreeSpaceEx("C:\\", NULL, &total, NULL);
```

**绕过：** 使用资源足够的 VM（4+ CPU、8GB+ RAM、100GB+ 磁盘）。

---

## Anti-DBI (Dynamic Binary Instrumentation)

### Frida Detection

```c
// 1. Check /proc/self/maps for frida-agent
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "frida") || strstr(line, "gadget")) exit(1);
}

// 2. Check for Frida's default port (27042)
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(27042), .sin_addr.s_addr=inet_addr("127.0.0.1")};
if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) exit(1);

// 3. Check for inline hooks (function prologue modification)
// Compare first bytes of libc functions against expected values
unsigned char *strcmp_bytes = (unsigned char *)strcmp;
if (strcmp_bytes[0] == 0xE9 || strcmp_bytes[0] == 0xFF) exit(1); // JMP = hooked

// 4. Thread name check
// Frida creates threads with names like "gmain", "gdbus", "frida-*"
DIR *dir = opendir("/proc/self/task");
while ((entry = readdir(dir))) {
    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);
    // Read comm and check for "gmain", "gdbus"
}

// 5. Named pipe detection (Windows)
// Frida creates \\.\pipe\frida-* named pipes
```

**用 Frida 绕 Frida 检测：**
```javascript
// Hook the detection functions themselves
Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter(args) {
        this.haystack = Memory.readUtf8String(args[0]);
        this.needle = Memory.readUtf8String(args[1]);
    },
    onLeave(retval) {
        if (this.needle && (this.needle.includes("frida") || this.needle.includes("gadget"))) {
            retval.replace(ptr(0)); // Not found
        }
    }
});

// Early Frida load (before anti-DBI runs)
// Use frida-gadget as early-init shared library
```

### Pin/DynamoRIO Detection

```c
// Check for instrumentation libraries in /proc/self/maps
// Pin: "pin-", "pinbin", "pinatrace"
// DynamoRIO: "dynamorio", "drcov", "drrun"

// Instruction count timing — DBI adds overhead
// Execute known instruction sequence, compare execution time
```

---

## Code Integrity / Self-Hashing

```c
// CRC32 over .text section
uint32_t crc = compute_crc32(text_start, text_size);
if (crc != EXPECTED_CRC) exit(1);  // Code was modified (breakpoints, patches)

// MD5/SHA256 of function bodies
unsigned char hash[32];
SHA256(function_addr, function_size, hash);
if (memcmp(hash, expected_hash, 32) != 0) exit(1);
```

**绕过：**
1. **硬件断点**（不修改代码，DR0-DR3）
2. **patch 比较**，令其总是成功
3. **hook 哈希函数**，返回预期值
4. **仿真而非调试**（Unicorn/Qiling，不修改代码）
5. **快照 + 对比：** dump 前后内存，diff 定位校验点

**循环中的自校验：**
```c
// Continuous integrity check in separate thread
void *watchdog(void *arg) {
    while (1) {
        if (compute_crc32(text_start, text_end - text_start) != saved_crc) {
            memset(flag_buffer, 0, flag_len);  // Destroy flag
            exit(1);
        }
        usleep(100000);
    }
}
```
**绕过：** 杀掉 watchdog 线程，或把其 sleep patch 成无限等待。

---

## Anti-Disassembly Techniques

### Opaque Predicates

```asm
; Condition that always evaluates the same way but looks data-dependent
mov eax, [some_memory]
imul eax, eax          ; x^2
and eax, 1             ; x^2 mod 2 is always 0 for any x
jnz fake_branch        ; Never taken, but disassembler doesn't know
; real code here
```

**识别：** 可用 Z3/SMT 证明分支恒真或恒假。

### Junk Bytes / Overlapping Instructions

```asm
jmp real_code
db 0xE8           ; Looks like start of CALL to linear disassembler
real_code:
mov eax, 1        ; Real code — disassembler may misalign here
```

**修复：** 切到图模式反汇编（Ghidra/IDA 处理较好）。手工方式是 undefine 后从正确偏移重新分析。

### Jump-in-the-Middle

```asm
; Jumps into the middle of a multi-byte instruction
eb 01          ; jmp +1 (skip next byte)
e8             ; fake CALL opcode — disassembler tries to decode as call
90             ; real: NOP (landed here from jmp)
```

### Function Chunking / Scattered Code

函数被拆成多个不连续 chunk，通过无条件跳转连接，破坏线性函数边界识别。

**工具：** IDA 的 “Append function tail” 或 Ghidra 在每个 chunk 处 “Create function”。

### Control Flow Flattening (Advanced)

超出基础 switch-case（见 patterns.md）的现代 OLLVM 变体还会用：
- **Bogus control flow：** 带 opaque predicate 的假分支
- **Instruction substitution：** `a + b` → `a - (-b)`，`a ^ b` → `(a | b) & ~(a & b)`
- **String encryption：** 字符串运行时解密，用后清除

**反混淆工具：**
- **D-810**（IDA 插件）：基于模式的反混淆、MBA 化简
- **GOOMBA**（Ghidra）：OLLLVM 自动反混淆
- **Miasm**：用于反混淆的符号执行
- **Arybo** / **SiMBA**：MBA 表达式化简

```bash
# D-810: install in IDA plugins directory, Edit → Plugins → D-810
# Simplifies MBA expressions: (a | b) & ~(a & b) → a ^ b
# Removes opaque predicates via pattern matching
```

### Mixed Boolean-Arithmetic (MBA) Identification & Simplification

```python
# Common MBA patterns and their simplified forms:
# (x & y) + (x | y) == x + y
# (x ^ y) + 2*(x & y) == x + y
# (x | y) - (x & ~y) == y
# ~(~x & ~y) == x | y (De Morgan's)
# (x | y) & ~(x & y) == x ^ y

# SiMBA tool for automated simplification:
# pip install simba-simplifier
from simba import simplify_mba
expr = "(a | b) + (a & b) - (~a & b)"
print(simplify_mba(expr))  # → a
```

CTF writeup 技巧见 [anti-analysis-ctf.md](anti-analysis-ctf.md)：包括用于模式切换的 SIGILL handler（Hack.lu 2015）、SIGFPE strace 侧信道（PlaidCTF 2017）、指令轨迹逆推（MeePwn 2017）、无 call 函数链（THC 2018），以及通过 `process_vm_writev` 导出父进程修补后的子进程二进制（Google CTF Quals 2018）。

---

## Comprehensive Bypass Strategies

### Universal Bypass Checklist

1. **识别所有反分析检查** - 搜索：`ptrace`、`IsDebuggerPresent`、`rdtsc`、`cpuid`、`NtQuery`、`GetTickCount`、`CheckRemoteDebuggerPresent`、`/proc/self`、`SIGTRAP`、`alarm`
2. **静态打补丁** - 运行前先用 pwntools 或 Ghidra NOP/patch 掉检查
3. **LD_PRELOAD**（Linux）- hook 返回伪值的 libc 函数
4. **ScyllaHide**（Windows x64dbg）- 自动 patch PEB 并 hook NT 函数
5. **仿真**（Unicorn/Qiling）- 不带调试器痕迹
6. **内核级绕过** - 修改 `/proc/sys/kernel/yama/ptrace_scope`，或用 `prctl`

### Layered Anti-Debug (Real-World Pattern)

许多 CTF 题会叠多层检查：
```text
1. TLS callback → IsDebuggerPresent（main 前）
2. main() → ptrace(TRACEME)
3. Watchdog thread → timing check + /proc scan
4. Code section → self-CRC32 integrity
5. Signal handler → real logic in SIGSEGV handler
```

**做法：** 先把所有检查找全，再系统性地逐个 patch 或 hook。若单独处理成本太高，直接改在仿真器中跑。

### Quick Reference: Check to Bypass

| Anti-Debug Check | Platform | Bypass |
|---|---|---|
| `ptrace(TRACEME)` | Linux | `LD_PRELOAD`、patch 成 `ret 0`、`catch syscall` |
| `IsDebuggerPresent` | Windows | ScyllaHide、Frida hook、PEB patch |
| `NtQueryInformationProcess` | Windows | ScyllaHide、hook ntdll |
| `rdtsc` timing | Both | NOP rdtsc、Frida 时间 hook、Pin |
| `/proc/self/status` | Linux | 挂载命名空间、hook fopen |
| `alarm(N)` | Linux | GDB 中 `handle SIGALRM ignore` |
| `SIGTRAP` handler | Linux | `handle SIGTRAP nostop pass` |
| `SIGFPE` handler side-channel | Linux | `strace -e signal=SIGFPE` 按输入计数 |
| TLS callback | Windows | 在 x64dbg 对 TLS 下断、patch |
| DR register scan | Windows | 用软件断点、hook GetThreadContext |
| INT3 scan / CRC | Both | 硬件断点、patch CRC 比较 |
| Frida detection | Both | 提前加载 gadget、hook strstr |
| CPUID hypervisor | Both | patch CPUID 返回、裸机 |
| Thread hiding | Windows | hook NtSetInformationThread |

---

### Trap-Flag Self-Check with cmovz Patcher (Hack.lu 2018)

**模式：** 二进制通过 `pushf; pop edx; and edx, 0x100` 检查 `EFLAGS` 的 Trap Flag，并把结果用于一个 `cmovz`，只有 TF 为 0 时才会覆写正确指令。GDB 单步时 TF 被置位，`cmovz` 永远不触发，程序会静默走错路径但不崩溃。

```asm
check_debugger:
    pushf
    pop   edx
    and   edx, 0x100          ; Trap Flag only
    test  edx, edx
    cmovz eax, ebx            ; overwrite `eax` only when NOT single-stepping
    mov   [rip+target], eax
```

**用硬件断点绕过：**
```gdb
(gdb) hbreak *0x56557267       # hardware BP, no INT3, no TF side effect
(gdb) run
(gdb) # inspect EAX at the hbreak — the patched value is now written
```

**关键点：** `pushf; pop reg; and reg, 0x100` 是检测 TF 最直接的方法之一，而且不会额外触发陷阱。单步会改变可见的 EFLAGS，也可能扰动流水线，因此软件断点加 `stepi` 会污染检查。硬件断点（`hbreak`）让指令正常执行、之后再停下，因此检查在“未调试”模式下通过。凡是读取 EFLAGS、RFLAGS、DR6 的反调试，都可优先考虑这一思路。

**References:** Hack.lu CTF 2018 — Forgetful Commander, writeup 11858

---

### SIGFPE Handler for mprotect Code Mutation (Hack.lu 2018)

**模式：** 二进制通过 `sys_sigaction` 安装自定义 `SIGFPE` handler，并故意构造会 trap 的算术指令（如除零 `div`）。handler 拿到内核传入的上下文后，对 `.text` 页调用 `mprotect` 令其可写，并改写原本保持不变的代码。静态分析看不到这次改写，因为正常路径不触发 FPE；普通动态分析也常漏掉，因为大多数调试器会先截获 SIGFPE。

```c
// Handler installed at startup
void on_fpe(int sig, siginfo_t *info, void *uap) {
    ucontext_t *ctx = uap;
    void *page = (void *)((uintptr_t)ctx->uc_mcontext.gregs[REG_RIP] & ~0xfff);
    mprotect(page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    // Patch a constant used by the next check
    *((uint32_t *)(page + 0x42)) = 0xDEADBEEF;
}
```

**绕过：**
```bash
# Let SIGFPE reach the program, not the debugger
gdb ./challenge
(gdb) handle SIGFPE nostop noprint pass
(gdb) break *on_fpe
(gdb) run
```

**关键点：** 通过 signal handler 执行 `mprotect` + 代码改写，会形成反编译器无法直接建模的跨边界控制流。`SIGFPE` 特别适合隐藏这类逻辑，因为正常执行中几乎不会出现。若在二进制中同时看到 `sys_sigaction(SIGFPE,...)` 或 `signal(SIGFPE,...)` 与 `mprotect`，应立刻用 `strace -e signal=SIGFPE` 跟踪 handler，并在第一次 FPE 前后对 `.text` 做 diff 标注改写区域。

**References:** Hack.lu CTF 2018 — Cheat Console, writeup 11868
