# CTF Reverse - 平台特定逆向

macOS/iOS、嵌入式/IoT 固件、内核驱动、汽车总线和游戏引擎逆向。

## Table of Contents
- [macOS / iOS Reversing](#macos--ios-reversing)
  - [Mach-O Binary Format](#mach-o-binary-format)
  - [Code Signing & Entitlements](#code-signing--entitlements)
  - [Objective-C Runtime RE](#objective-c-runtime-re)
  - [Swift Binary Reversing](#swift-binary-reversing)
  - [iOS App Analysis](#ios-app-analysis)
  - [dyld / Dynamic Linking](#dyld--dynamic-linking)
- [Embedded / IoT Firmware RE](#embedded--iot-firmware-re)
  - [Firmware Extraction](#firmware-extraction)
  - [Firmware Unpacking](#firmware-unpacking)
  - [Architecture-Specific Notes](#architecture-specific-notes)
  - [RTOS Analysis](#rtos-analysis)
- [Kernel Driver Reversing](#kernel-driver-reversing)
  - [Linux Kernel Modules](#linux-kernel-modules)
  - [eBPF Programs](#ebpf-programs)
  - [Windows Kernel Drivers](#windows-kernel-drivers)
- [Game Engine Reversing](#game-engine-reversing)
  - [Unreal Engine](#unreal-engine)
  - [Unity (Beyond IL2CPP)](#unity-beyond-il2cpp)
  - [Anti-Cheat Analysis](#anti-cheat-analysis)
  - [Lua-Scripted Games](#lua-scripted-games)
- [Automotive / CAN Bus RE](#automotive--can-bus-re)
- [RISC-V QEMU Execution with GLIBC Symbol Version Patching (Pwn2Win 2018)](#risc-v-qemu-execution-with-glibc-symbol-version-patching-pwn2win-2018)
- [APK Certificate SHA-256 as AES Key (ASIS Finals 2018)](#apk-certificate-sha-256-as-aes-key-asis-finals-2018)
- [Moxie ISA Custom Opcode Discovery (SECCON 2018)](#moxie-isa-custom-opcode-discovery-seccon-2018)
- [Unity APK Assembly-CSharp.dll Runtime Patch (SECCON 2018)](#unity-apk-assembly-csharpdll-runtime-patch-seccon-2018)
- [Il2CppDumper for Unity IL2CPP Metadata Recovery (SECCON 2018)](#il2cppdumper-for-unity-il2cpp-metadata-recovery-seccon-2018)

---

## macOS / iOS Reversing

### Mach-O Binary Format

```bash
# File identification
file binary                    # "Mach-O 64-bit executable arm64" or "x86_64"
otool -l binary               # Load commands (segments, dylibs, entry point)
otool -L binary               # Linked dynamic libraries

# Universal (fat) binaries — multiple architectures in one file
lipo -info universal_binary    # List architectures
lipo universal_binary -thin arm64 -output binary_arm64  # Extract one arch

# Segments and sections
otool -l binary | grep -A5 "segment\|section"
# Key segments: __TEXT (code), __DATA (globals), __LINKEDIT (symbols)
# Key sections: __text (instructions), __cstring (C strings), __objc_methname
```

**Mach-O 关键概念：**
- Load command 驱动动态链接器 `dyld`
- `LC_MAIN` 表示入口点（取代旧的 `LC_UNIXTHREAD`）
- `LC_LOAD_DYLIB` 表示依赖的动态库
- `LC_CODE_SIGNATURE` 表示代码签名 blob
- `__DATA_CONST.__got` 是 GOT
- `__DATA.__la_symbol_ptr` 是延迟解析符号指针，类似 PLT

### Code Signing & Entitlements

```bash
# Check code signature
codesign -dvvv binary
codesign --verify binary

# Extract entitlements (capability permissions)
codesign -d --entitlements - binary
# Key entitlements: com.apple.security.app-sandbox, com.apple.security.network.client

# Remove code signature (for patching)
codesign --remove-signature binary

# Re-sign (ad-hoc, for testing)
codesign -f -s - binary
```

**CTF 相关：** 修改后的 macOS 二进制通常需要重新签名才能运行。本地测试一般用 ad-hoc 签名（`-s -`）即可。

### Objective-C Runtime RE

```bash
# Dump Objective-C class info
class-dump binary > classes.h
# Shows: @interface, @protocol, method signatures with types

# Runtime inspection with lldb
(lldb) expression -l objc -O -- [NSClassFromString(@"ClassName") new]
(lldb) expression -l objc -O -- [[ClassName alloc] init]

# Method swizzling detection (anti-tamper)
# Look for: method_exchangeImplementations, class_replaceMethod
```

**反汇编中的 Objective-C：**
```text
# objc_msgSend(receiver, selector, ...) is THE dispatch mechanism
# RDI = self (receiver), RSI = selector (char* method name)

# In Ghidra/IDA, look for:
objc_msgSend(obj, "checkPassword:", input)
# Selector strings are in __objc_methname section
# Cross-reference selectors to find implementations
```

**class-dump 替代：**
- `dsdump`：更快，支持 Swift + Objective-C
- `otool -oV binary`：导出 Objective-C 段
- Ghidra：分析选项中启用 Objective-C analyzer

### Swift Binary Reversing

```bash
# Detect Swift
strings binary | grep "swift"
otool -l binary | grep "swift"   # __swift5_* sections

# Swift demangling
swift demangle 's14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# xcrun swift-demangle < mangled_names.txt
```

**反汇编中的 Swift：**
```text
# Swift uses value witness tables (VWT) for type operations
# Protocol witness tables (PWT) for dynamic dispatch (like vtables)

# Key runtime functions to watch:
swift_allocObject          → heap allocation
swift_release             → reference count decrement
swift_bridgeObjectRetain  → bridged (ObjC ↔ Swift) retain
swift_once                → lazy initialization (like dispatch_once)

# String layout:
# Small strings (≤15 bytes): inline in 16-byte buffer, tagged pointer
# Large strings: heap-allocated, pointer + length + flags

# Array<T>: pointer to ContiguousArrayStorage (header + elements)
# Dictionary<K,V>: hash table with open addressing
```

**Ghidra 对 Swift：** 启用 Swift 语言模块。`__swift5_types`、`__swift5_proto` 等 metadata section 可被解析为类型描述符。

### iOS App Analysis

```bash
# Extract IPA (iOS app package)
unzip app.ipa -d extracted/
ls extracted/Payload/*.app/

# Check if encrypted (App Store encryption / FairPlay DRM)
otool -l extracted/Payload/*.app/binary | grep -A4 "LC_ENCRYPTION_INFO"
# cryptid = 1 means encrypted, 0 means decrypted

# Decrypt with frida-ios-dump (requires jailbroken device)
# Or use Clutch / bfdecrypt on device
frida-ios-dump -H jailbroken_ip -p 22 "App Name"

# Analyze decrypted binary
class-dump decrypted_binary > headers.h
```

**越狱检测与绕过：**
```javascript
// Common jailbreak checks:
// 1. Check for Cydia/Sileo
// 2. Check /private/var/lib/apt
// 3. fork() succeeds (sandboxed apps can't fork)
// 4. Open /etc/apt, /bin/sh with write
// 5. Check for substrate/substitute libraries

// Frida bypass:
var paths = ["/Applications/Cydia.app", "/bin/sh", "/etc/apt",
             "/private/var/lib/apt", "/usr/bin/ssh"];
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter(args) {
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave(retval) {
        if (paths.some(p => this.path && this.path.includes(p))) {
            retval.replace(-1);  // File not found
        }
    }
});
```

### dyld / Dynamic Linking

```bash
# DYLD environment variables (for analysis, blocked in hardened runtime)
DYLD_PRINT_LIBRARIES=1 ./binary       # Print loaded dylibs
DYLD_INSERT_LIBRARIES=hook.dylib ./binary  # Inject dylib (like LD_PRELOAD)
# Note: SIP (System Integrity Protection) blocks this for system binaries

# Inspect dyld shared cache (contains all system frameworks)
dyld_shared_cache_util -list /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

---

## Embedded / IoT Firmware RE

### Firmware Extraction

```bash
# binwalk — firmware analysis and extraction
binwalk firmware.bin                        # Identify embedded filesystems, compressed data
binwalk -e firmware.bin                     # Extract all identified components
binwalk -Me firmware.bin                    # Recursive extraction (matryoshka)
binwalk --dd='.*' firmware.bin              # Extract everything raw

# Manual extraction by signature
strings firmware.bin | head -50             # Look for version strings, filesystem markers
hexdump -C firmware.bin | grep "hsqs"       # SquashFS magic
hexdump -C firmware.bin | grep "UBI#"       # UBI magic
```

**物理提取方式：**
```text
UART:  串口控制台，常可拿到 root shell 或 bootloader
       工具：USB-UART 适配器，波特率探测（通常 115200）
       识别：4 个针脚（GND/TX/RX/VCC）

JTAG:  直接 CPU 调试，可读写 flash、停机、下断点
       工具：OpenOCD、J-Link、Bus Pirate
       识别：10/14/20 针接口，可用 JTAGulator 探测

SPI Flash: 直接读取闪存芯片
           工具：flashrom、CH341A
           识别：8 脚 SOIC 芯片

eMMC:  常见于路由器、手机
       工具：eMMC reader，或直接焊接测试点
```

### Firmware Unpacking

```bash
# SquashFS (most common in routers)
unsquashfs -d output/ squashfs-root.sqfs
# If custom compression: try different compressors (-comp xz|lzma|lzo|gzip)

# JFFS2
jefferson -d output/ jffs2.img

# UBI/UBIFS
ubireader_extract_images firmware.ubi
ubireader_extract_files ubifs.img

# CPIO (initramfs)
cpio -idv < initramfs.cpio

# Device tree blob
dtc -I dtb -O dts -o output.dts device_tree.dtb

# Kernel extraction
binwalk -e firmware.bin
# Look for: zImage, uImage, vmlinux
# Extract vmlinux from compressed: vmlinux-to-elf tool
```

### Architecture-Specific Notes

**ARM（IoT 中最常见）：**
```bash
# Cross-toolchain
apt install gcc-arm-linux-gnueabihf gdb-multiarch

# QEMU emulation
qemu-arm -L /usr/arm-linux-gnueabihf/ ./arm_binary
qemu-arm -g 1234 ./arm_binary    # Start GDB server on port 1234
gdb-multiarch -ex 'target remote :1234' ./arm_binary

# ARM vs Thumb: ARM instructions are 4 bytes, Thumb are 2 bytes
# LSB of function pointer indicates mode: 0=ARM, 1=Thumb
# Ghidra: Right-click → Processor Options → ARM/Thumb mode
```

**ARM64/AArch64：** 调用约定、ROP gadget 和 `qemu-aarch64-static` 仿真见 [platforms-hardware.md](platforms-hardware.md#arm64aarch64-reversing-and-exploitation)。

**MIPS（路由器、嵌入式）：**
```bash
# Big-endian vs little-endian — check ELF header or file command
file binary    # "MIPS, MIPS32 rel2 (MIPS-II), big-endian" or "little-endian"

# Emulation
qemu-mips -L /usr/mips-linux-gnu/ ./mips_binary         # Big-endian
qemu-mipsel -L /usr/mipsel-linux-gnu/ ./mipsel_binary   # Little-endian

# Key MIPS patterns:
# Branch delay slots — instruction AFTER branch always executes
# $gp (global pointer) — used for PIC, points to .got
# lui + addiu pair — loads 32-bit constant (upper 16 + lower 16)
```

**RISC-V：** 基础分析见 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)，高级扩展与调试见 [platforms-hardware.md](platforms-hardware.md#risc-v-advanced)。

### RTOS Analysis

```text
FreeRTOS:
  - 任务类似线程：xTaskCreate → function pointer + stack
  - 字符串："IDLE", "Tmr Svc", task names
  - xQueueSend/xQueueReceive → 任务间通信
  - 关注 vTaskDelay()、xSemaphoreTake()

Zephyr:
  - k_thread_create → 创建线程
  - k_msgq_put/k_msgq_get → 消息队列
  - CONFIG_* 符号暴露内核配置

Bare metal:
  - 中断向量表常在 0x0 或 0x08000000
  - 主循环模式：while(1) { read_input(); process(); output(); }
  - 外设寄存器通常是内存映射地址
```

---

## Kernel Driver Reversing

### Linux Kernel Modules

```bash
# Identify kernel module
file module.ko                      # "ELF 64-bit LSB relocatable"
modinfo module.ko                   # Module info (description, author, license)

# List module symbols
nm module.ko | grep -v " U "       # Exported symbols

# Strings for quick recon
strings module.ko | grep -i "flag\|secret\|ioctl\|device"

# Find ioctl handler
# Key pattern: .unlocked_ioctl = my_ioctl_handler in file_operations struct
# In Ghidra: find struct with function pointers, identify by position
```

**常见模式：**
```c
// Device creation (creates /dev/challenge)
alloc_chrdev_region(&dev, 0, 1, "challenge");
cdev_init(&cdev, &fops);

// ioctl handler (main interface)
long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case CUSTOM_CMD_1: /* operation */ break;
        case CUSTOM_CMD_2: /* operation */ break;
    }
}

// copy_from_user / copy_to_user — data transfer with userspace
copy_from_user(kernel_buf, (void __user *)arg, size);
copy_to_user((void __user *)arg, kernel_buf, size);
```

**调试：**
```bash
# QEMU + GDB for kernel debugging
qemu-system-x86_64 -kernel bzImage -initrd initrd.cpio -s -S \
  -append "console=ttyS0 nokaslr" -nographic

# In another terminal
gdb vmlinux
(gdb) target remote :1234
(gdb) lx-symbols           # Load module symbols (requires scripts)
(gdb) add-symbol-file module.ko 0x<loaded_address>
```

### eBPF Programs

```bash
# Dump eBPF programs from running system
bpftool prog list
bpftool prog dump xlated id <N>    # Disassemble
bpftool prog dump jited id <N>     # JIT'd machine code

# Disassemble .o file containing eBPF
llvm-objdump -d ebpf_prog.o
```

**eBPF 关注点：**
- 11 个寄存器（`r0-r10`），64 位
- `r0` 为返回值，`r1-r5` 为参数，`r10` 为 frame pointer
- 指令宽度固定 8 字节
- 常见 helper：`bpf_map_lookup_elem`、`bpf_map_update_elem`、`bpf_probe_read`、`bpf_trace_printk`

### Windows Kernel Drivers

```bash
# .sys files are PE format — load in IDA/Ghidra as normal PE
# Entry point: DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)

# Key patterns:
# IoCreateDevice → creates device object
# IRP_MJ_DEVICE_CONTROL → ioctl handler
# MmMapIoSpace → memory-mapped I/O
# ObReferenceObjectByHandle → get kernel object from handle
# ZwCreateFile/ZwReadFile → kernel-mode file operations
```

---

## Game Engine Reversing

### Unreal Engine

```bash
# Pak file extraction
# UnrealPakTool or quickbms with unreal_tournament_4.bms
unrealpak.exe extract GameName.pak -output extracted/

# UE4/UE5 asset formats:
# .uasset — serialized UObject (meshes, textures, blueprints)
# .umap — level/map data
# .ushaderbytecode — compiled shader
# FModel (https://fmodel.app/) — GUI asset viewer/extractor
```

**Blueprint 逆向：**
```text
Blueprint 会编译为 .uasset 中的字节码。
- 用 UAssetGUI / FModel 浏览 Blueprint 资源
- Kismet bytecode 表示可视化脚本逻辑
- 常见节点：K2_SetTimer、DoOnce、Branch、Custom Events
- flag 逻辑经常藏在 Blueprint 事件图，而不是 C++
```

**UE4/UE5 C++ 逆向：**
```bash
# Key engine classes:
# UObject → base class for everything
# AActor → entities in the world
# UGameInstance → game state
# APlayerController → player input handling

# Reflection system — UCLASS(), UPROPERTY(), UFUNCTION() macros
# Generates metadata accessible at runtime
# In Ghidra: look for UClass::StaticClass() calls → type identification

# String handling: FString (UTF-16), FName (hashed identifier), FText (localized)
# In memory: FString = {TCHAR* Data, int32 ArrayNum, int32 ArrayMax}
```

### Unity (Beyond IL2CPP)

IL2CPP 基础见 [languages.md](languages.md#unity-il2cpp-games)。

**Mono Unity：**
```bash
# Managed assemblies in Data/Managed/ directory
# Assembly-CSharp.dll contains game logic
dnspy Assembly-CSharp.dll       # Full decompilation + debugging
ilspy Assembly-CSharp.dll       # Decompilation only

# Common Unity patterns:
# MonoBehaviour.Start() → initialization
# MonoBehaviour.Update() → per-frame logic
# PlayerPrefs.GetString("key") → stored data
# SceneManager.LoadScene("level") → scene transitions
```

**Unity 资源提取：**
```bash
# AssetStudio — extract textures, models, audio, scripts
# AssetRipper — comprehensive Unity asset extraction
# UABE (Unity Asset Bundle Extractor) — low-level asset editing
```

常见搜索位置：
- 文本资源（`.txt`、`.json`）
- TextMesh / UI Text
- shader 源码
- ScriptableObject
- PlayerPrefs 存档

### Anti-Cheat Analysis

```text
EasyAntiCheat (EAC):
- 内核驱动 + 用户态模块
- 检查游戏内存完整性

BattlEye:
- BEService.exe + BEClient.dll
- 加密通信、截图、进程扫描

Valve Anti-Cheat (VAC):
- 仅用户态
- 模块哈希、内存扫描、服务端检测

CTF 处理思路：
1. 先识别具体 anti-cheat
2. CTF 中通常只需绕一个具体检查，不必完全对抗整套系统
3. 也可优先考虑改存档而非运行时作弊
```

### Lua-Scripted Games

```bash
# Many games embed Lua for scripting
# Look for: lua51.dll, luajit.dll, .lua files in assets

# Luac bytecode decompilation
luadec bytecode.luac > decompiled.lua      # Lua 5.1-5.3
unluac bytecode.luac > decompiled.lua      # Alternative

# LuaJIT bytecode
luajit -bl bytecode.lua                     # Disassemble
# ljd (LuaJIT decompiler): python3 ljd bytecode.lua

# Embedded Lua: strings binary | grep "lua_\|luaL_\|LUA_"
# Hook lua_pcall to intercept script execution
```

---

## Automotive / CAN Bus RE

```bash
# CAN bus interface setup
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# Capture CAN traffic
candump can0                               # Live capture
candump -l can0                            # Log to file
cansniffer can0                            # Filter/highlight changes

# Replay CAN messages
canplayer -I logfile.log can0
cansend can0 7DF#0201000000000000          # Send single frame (OBD-II request)
```

**汽车题常见模式：**
- Seed-key 绕过：从 ECU 固件中逆 key 派生算法
- CAN 报文重放：抓合法控制帧再重放
- 通过 UDS/KWP2000 从 ECU 提取固件

---

## RISC-V QEMU Execution with GLIBC Symbol Version Patching (Pwn2Win 2018)

**模式：** 题目二进制依赖某个本地没有的 RISC-V Debian 运行环境。可提取 Debian 中的 libc6 和动态链接器，然后把二进制要求的 GLIBC 符号版本（如 `GLIBC_2.25`）改成现有版本（如 `GLIBC_2.27`），再用 `qemu-riscv64 -L <sysroot>` 跑。

```bash
ar x libc6_2.27-5_riscv64.deb && tar xf data.tar.xz
sed 's@GLIBC_2.25@GLIBC_2.27@g' -i binary
# Patch the symbol version hash too
objdump -p binary   # note old hash
# replace bytes with xxd / hexedit
qemu-riscv64 -L ./sysroot ./binary
```

**关键点：** `ld.so` 的符号版本校验并不只看字符串，还会看旁边的 hash。必须同时改版本字符串和 hash，才能真正绕过。

**参考：** Pwn2Win CTF 2018 — Too Slow, writeup 12501+

---

## APK Certificate SHA-256 as AES Key (ASIS Finals 2018)

**模式：** Android 应用把 `SHA-256(packageInfo.signatures[0].toByteArray())` 的前 16 字节当 AES key。由于签名证书就打包在 APK 里，因此 key 可离线恢复，无需逆 native 代码。

```python
from hashlib import sha256
import base64, zipfile

cert = zipfile.ZipFile('app.apk').read('META-INF/CERT.RSA')
key  = base64.b64encode(sha256(cert).digest())[:16]
# Decrypt config resources with AES-ECB using this key
```

**关键点：** “从公开指纹确定性派生密钥”是常见 Android 反模式。遇到 `getSignature`、`getPackageInfo`、`MessageDigest` 组合时，应警惕这种设计。

**参考：** ASIS CTF Finals 2018 — Gunshop, writeup 12420

---

## Moxie ISA Custom Opcode Discovery (SECCON 2018)

**模式：** 程序运行在冷门架构 Moxie 上。对 ELF 做 `strings` 会发现帮助文本里直接写着自定义 opcode `SETRSEED (0x16)` 与 `GETRAND (0x17)`，以及一个非标准 `xorshift32` 变体。只要在 Python 里模拟这两个指令，就能恢复 PRNG 序列并解密。

```python
def xorshift32(s):
    s ^= (s << 13) & 0xffffffff
    s ^= (s >> 17)
    s ^= (s << 15) & 0xffffffff     # Note: *not* standard (<< 5)
    return s & 0xffffffff
```

**关键点：** 冷门 ISA 题常把少量自定义指令直接写在帮助文本或调试输出中。先搜人类可读字符串，往往比先实现整套模拟器更快。

**参考：** SECCON 2018 — Special Instructions, writeup 12001

---

## Unity APK Assembly-CSharp.dll Runtime Patch (SECCON 2018)

**模式：** Unity 游戏把 C# 逻辑放在 `assets/bin/Data/Managed/Assembly-CSharp.dll` 中。可用 dnSpy/ILSpy 反编译并修改 `Update()` / `Start()` 等方法，重新打包 APK 并签名安装。

```bash
apktool d game.apk -o game_src
# Replace game_src/assets/bin/Data/Managed/Assembly-CSharp.dll with patched version
apktool b game_src -o patched.apk
jarsigner -keystore debug.keystore -storepass android patched.apk androiddebugkey
adb install -r patched.apk
```

**关键点：** Unity Mono 游戏本质上就是“可反编译的 C#”。如果 flag 因动画、旋转、遮罩等效果不可见，最直接的方法就是改 DLL 逻辑。

**参考：** SECCON 2018 — block, writeup 12001

---

## Il2CppDumper for Unity IL2CPP Metadata Recovery (SECCON 2018)

**模式：** 新版 Unity 常使用 IL2CPP（原生代码 + metadata），不再直接提供 `Assembly-CSharp.dll`。此时应对 `libil2cpp.so` 与 `assets/bin/Data/Managed/Metadata/global-metadata.dat` 使用 `Il2CppDumper`，再 grep 输出中的端点、API 路径或加密常量。

```bash
Il2CppDumper libil2cpp.so global-metadata.dat out/
grep -r "https://" out/  # find hardcoded endpoints
```

**关键点：** IL2CPP 看似全是本地代码，但 metadata 文件仍保存了类型名、方法名和字符串常量。对多数 CTF 题而言，这些信息已经足够恢复核心逻辑。

**参考：** SECCON 2018 — shooter, writeup 12001
