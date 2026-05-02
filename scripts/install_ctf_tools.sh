#!/usr/bin/env bash
# shellcheck disable=SC2024  # 重定向目标为用户拥有的日志文件，而非 sudo
# 为 solve-challenge 技能引导通用工具。
#
# 用法：
#   bash scripts/install_ctf_tools.sh [OPTIONS] MODE
#
# 模式：
#   python, apt, brew, gems, go, manual, all, --verify
#
# 选项：
#   --dry-run   显示将要安装的内容，但不执行安装
#   --force     即使已安装也重新安装包
#
# 示例：
#   bash scripts/install_ctf_tools.sh all
#   bash scripts/install_ctf_tools.sh --dry-run all
#   bash scripts/install_ctf_tools.sh --force python
#   bash scripts/install_ctf_tools.sh --verify

set -euo pipefail

# ---------------------------------------------------------------------------
# 全局变量
# ---------------------------------------------------------------------------

DRY_RUN=false
FORCE=false
MODE=""
FAILED=()
SUCCEEDED=()
SKIPPED=()
LOG_DIR="${HOME}/.ctf-tools"
LOG_FILE=""
CTF_VENV="${HOME}/.ctf-tools/venv"

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --force) FORCE=true; shift ;;
    -*) if [ -z "$MODE" ]; then MODE="$1"; shift; else echo "未知选项: $1" >&2; exit 2; fi ;;
    *) MODE="$1"; shift ;;
  esac
done
MODE="${MODE:-all}"

# ---------------------------------------------------------------------------
# 日志记录
# ---------------------------------------------------------------------------

setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/install-$(date +%Y-%m-%d_%H%M%S).log"
  log_info "日志记录到 $LOG_FILE"
}

log_info() { echo "==> $*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_warn() { echo "警告: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_error() { echo "错误: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_detail() { echo "    $*" >> "${LOG_FILE:-/dev/null}"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "需要 '$cmd' 但在 PATH 中未找到"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# 已安装跳过检查
# ---------------------------------------------------------------------------

# 检查 Python 模块是否可导入。
py_module_installed() {
  python3 -c "import $1" 2>/dev/null
}

# 检查 apt 包是否已安装。
apt_pkg_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

# 检查 Homebrew 配方是否已安装。
brew_pkg_installed() {
  brew list --formula "$1" >/dev/null 2>&1
}

# 检查 Ruby gem 是否已安装。
gem_installed() {
  gem list -i "^${1}$" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Pip 包列表 — name=version:import_module
#
# 格式: "pip_name==version:import_name"
# import_name 用于已安装跳过检查。
# ---------------------------------------------------------------------------

PIP_PACKAGES=(
  "pwntools==4.15.0:pwn"
  "pycryptodome==3.23.0:Crypto"
  "z3-solver==4.13.0.0:z3"
  "sympy==1.14.0:sympy"
  "gmpy2==2.3.0:gmpy2"
  "hashpumpy==1.2:hashpumpy"
  "fpylll==0.6.4:fpylll"
  "py_ecc==8.0.0:py_ecc"
  "angr==9.2.193:angr"
  "frida-tools==14.8.0:frida"
  "qiling==1.4.6:qiling"
  "requests==2.32.5:requests"
  "flask-unsign==1.2.1:flask_unsign"
  "sqlmap==1.10.3:sqlmap"
  "ropper==1.13.13:ropper"
  "ROPgadget==7.7:ropgadget"
  "volatility3==2.27.0:volatility3"
  "yara-python==4.5.4:yara"
  "pefile==2024.8.26:pefile"
  "capstone==5.0.3:capstone"
  "oletools==0.60.2:oletools"
  "unicorn==2.1.2:unicorn"
  "scapy==2.7.0:scapy"
  "Pillow==11.3.0:PIL"
  "numpy==2.2.6:numpy"
  "matplotlib==3.10.8:matplotlib"
  "shodan==1.31.0:shodan"
  "uncompyle6==3.9.3:uncompyle6"
  "lief==0.17.6:lief"
  "dnspython==2.8.0:dns"
  "dnslib==0.9.26:dnslib"
  "dissect.cobaltstrike==1.2.1:dissect.cobaltstrike"
)

# ---------------------------------------------------------------------------
# 安装器
# ---------------------------------------------------------------------------

install_python() {
  require_cmd python3 || return 1

  local pip_flags=()

  # PEP 668: 优先创建专用虚拟环境而非使用 --user
  if python3 -c "import sysconfig; marker = sysconfig.get_path('stdlib') + '/EXTERNALLY-MANAGED'; open(marker)" 2>/dev/null; then
    if [ -z "${VIRTUAL_ENV:-}" ]; then
      if [ "$DRY_RUN" = true ]; then
        log_info "检测到 PEP 668 — 将创建虚拟环境于 $CTF_VENV"
      else
        log_info "检测到 PEP 668 — 正在创建虚拟环境于 $CTF_VENV"
        python3 -m venv "$CTF_VENV" 2>>"${LOG_FILE:-/dev/null}" || {
          log_warn "虚拟环境创建失败 — 回退使用 --user"
          pip_flags+=(--user)
        }
        if [ -d "$CTF_VENV" ] && [ -z "${pip_flags[*]:-}" ]; then
          # shellcheck disable=SC1091
          source "$CTF_VENV/bin/activate"
          log_info "已激活虚拟环境: $CTF_VENV"
          log_info "复用方法: source $CTF_VENV/bin/activate"
        fi
      fi
    fi
  fi

  # 如果是基于 apt 的系统，先安装 libgmp-dev — gmpy2 依赖
  if command -v apt-get >/dev/null 2>&1; then
    if ! dpkg -s libgmp-dev >/dev/null 2>&1; then
      if [ "$DRY_RUN" = true ]; then
        log_info "将安装 libgmp-dev（gmpy2 依赖）"
      else
        log_info "正在安装 libgmp-dev（gmpy2 依赖）"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q libgmp-dev >>"${LOG_FILE:-/dev/null}" 2>&1 || log_warn "无法安装 libgmp-dev"
      fi
    fi
  fi

  # 第一遍：收集需要安装的包
  local to_install=()
  local to_install_display=()
  for entry in "${PIP_PACKAGES[@]}"; do
    local spec="${entry%%:*}"
    local mod="${entry##*:}"
    local name="${spec%%==*}"

    if [ "$FORCE" = false ] && py_module_installed "$mod"; then
      SKIPPED+=("pip:$name")
      continue
    fi
    to_install+=("$spec")
    to_install_display+=("$name")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "Python: 所有 ${#PIP_PACKAGES[@]} 个包均已安装"
    return 0
  fi

  log_info "Python: 需要安装 ${#to_install[@]}/${#PIP_PACKAGES[@]} 个包（跳过 ${#SKIPPED[@]} 个）"

  if [ "$DRY_RUN" = true ]; then
    log_info "将安装: ${to_install_display[*]}"
    return 0
  fi

  # 尝试批量安装（pip 内部处理并行）
  log_info "尝试批量安装 ${#to_install[@]} 个包"
  if python3 -m pip install "${pip_flags[@]}" "${to_install[@]}" >>"$LOG_FILE" 2>&1; then
    for entry in "${to_install_display[@]}"; do
      SUCCEEDED+=("pip:$entry")
    done
    log_info "批量安装成功"
    return 0
  fi

  # 批量安装失败 — 回退逐个安装
  log_warn "批量安装失败 — 回退逐个安装"
  for entry in "${PIP_PACKAGES[@]}"; do
    local spec="${entry%%:*}"
    local mod="${entry##*:}"
    local name="${spec%%==*}"
    if [ "$FORCE" = false ] && py_module_installed "$mod"; then
      continue
    fi

    if python3 -m pip install "${pip_flags[@]}" "$spec" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("pip:$name")
    else
      log_warn "pip 安装失败: $name"
      log_detail "失败命令: python3 -m pip install ${pip_flags[*]} $spec"
      FAILED+=("pip:$name")
    fi
  done
}

install_apt() {
  require_cmd apt-get || return 1

  local packages=(
    gdb radare2 binutils binwalk foremost libimage-exiftool-perl
    tshark sleuthkit ffmpeg steghide testdisk john pcapfix
    nmap whois dnsutils hashcat strace ltrace imagemagick curl jq
    apktool upx qemu-system-x86 sagemath qrencode
  )

  # 收集需要安装的软件包
  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && apt_pkg_installed "$pkg"; then
      SKIPPED+=("apt:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "apt: 所有 ${#packages[@]} 个软件包已安装"
    return 0
  fi

  log_info "apt: 需要安装 ${#to_install[@]}/${#packages[@]} 个软件包（跳过 ${#SKIPPED[@]} 个）"

  if [ "$DRY_RUN" = true ]; then
    log_info "将安装: ${to_install[*]}"
    return 0
  fi

  log_info "正在更新 apt 软件包列表"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -q >>"$LOG_FILE" 2>&1 || log_warn "apt-get update 失败"

  for pkg in "${to_install[@]}"; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("apt:$pkg")
    else
      log_warn "apt 安装失败: $pkg"
      FAILED+=("apt:$pkg")
    fi
  done
}

install_brew() {
  require_cmd brew || return 1

  local packages=(
    gdb radare2 binutils binwalk exiftool wireshark sleuthkit
    ffmpeg testdisk john-jumbo nmap whois bind hashcat ghidra
    imagemagick curl jq apktool upx qemu qrencode
  )

  # 收集需要安装的软件包
  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && brew_pkg_installed "$pkg"; then
      SKIPPED+=("brew:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "brew: 所有 ${#packages[@]} 个软件包已安装"
    return 0
  fi

  log_info "brew: 需要安装 ${#to_install[@]}/${#packages[@]} 个软件包（跳过 ${#SKIPPED[@]} 个）"

  if [ "$DRY_RUN" = true ]; then
    log_info "将安装: ${to_install[*]}"
    return 0
  fi

  for pkg in "${to_install[@]}"; do
    if brew install "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("brew:$pkg")
    else
      log_warn "brew 安装失败: $pkg"
      FAILED+=("brew:$pkg")
    fi
  done
}

install_gems() {
  if ! command -v gem >/dev/null 2>&1; then
    log_warn "未找到 gem — 跳过 Ruby gem 安装（请安装 Ruby 以启用）"
    SKIPPED+=(gem:one_gadget gem:seccomp-tools gem:zsteg)
    return 0
  fi

  local packages=(one_gadget seccomp-tools zsteg)

  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && gem_installed "$pkg"; then
      SKIPPED+=("gem:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "gems: 所有 ${#packages[@]} 个 gem 已安装"
    return 0
  fi

  log_info "gems: 需要安装 ${#to_install[@]}/${#packages[@]} 个"

  if [ "$DRY_RUN" = true ]; then
    log_info "将安装: ${to_install[*]}"
    return 0
  fi

  for pkg in "${to_install[@]}"; do
    if gem install "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("gem:$pkg")
    else
      log_warn "gem 安装失败: $pkg"
      FAILED+=("gem:$pkg")
    fi
  done
}

install_go() {
  if ! command -v go >/dev/null 2>&1; then
    log_warn "未找到 go — 跳过 Go 工具安装（请安装 Go 以启用）"
    SKIPPED+=(go:ffuf)
    return 0
  fi

  if [ "$FORCE" = false ] && command -v ffuf >/dev/null 2>&1; then
    log_info "go: ffuf 已安装"
    SKIPPED+=(go:ffuf)
    return 0
  fi

  if [ "$DRY_RUN" = true ]; then
    log_info "将安装: ffuf"
    return 0
  fi

  log_info "正在安装 Go 工具"
  if go install github.com/ffuf/ffuf/v2@latest >>"$LOG_FILE" 2>&1; then
    SUCCEEDED+=(go:ffuf)
  else
    log_warn "go 安装失败: ffuf"
    FAILED+=(go:ffuf)
  fi
}

print_manual() {
  cat <<'EOF'
手动安装（无法可靠自动化）:
  pwndbg     — Linux: https://github.com/pwndbg/pwndbg
               macOS: brew install pwndbg/tap/pwndbg-gdb
  RsaCtfTool — git clone https://github.com/RsaCtfTool/RsaCtfTool
  SageMath   — Linux: apt install sagemath
               macOS: brew install --cask sage
  steghide   — Linux: apt install steghide
               Homebrew 不可用
  pycdc      — git clone https://github.com/zrax/pycdc && cmake . && make
               （Python 3.9+ 字节码反编译器；uncompyle6 仅支持 <=3.8）
  dnSpy      — https://github.com/dnSpy/dnSpy （仅限 Windows/.NET）
EOF
}

# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------

verify() {
  local missing=()
  local found=()

  # 如果存在 ctf-tools 虚拟环境则激活（软件包安装在其中）
  if [ -d "$CTF_VENV/bin" ] && [ -z "${VIRTUAL_ENV:-}" ]; then
    # shellcheck disable=SC1091
    source "$CTF_VENV/bin/activate" 2>/dev/null && log_info "使用虚拟环境: $CTF_VENV"
  fi

  local -a checks=(
    python3 gdb r2 objdump binwalk exiftool tshark fls ffmpeg
    testdisk john nmap whois hashcat strace ltrace convert curl jq
    apktool upx qemu-system-x86_64 qrencode ffuf gem go
  )

  log_info "正在验证工具可用性"
  for cmd in "${checks[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      found+=("$cmd")
    else
      missing+=("$cmd")
    fi
  done

  # Python 模块 — 使用 PIP_PACKAGES 中相同的映射
  for entry in "${PIP_PACKAGES[@]}"; do
    local mod="${entry##*:}"
    local spec="${entry%%:*}"
    local name="${spec%%==*}"
    if python3 -c "import $mod" 2>/dev/null; then
      found+=("py:$name")
    else
      missing+=("py:$name")
    fi
  done

  echo ""
  echo "已找到: ${#found[@]} 个工具/模块"
  echo "缺失: ${#missing[@]} 个工具/模块"
  if [ ${#missing[@]} -gt 0 ]; then
    echo ""
    echo "缺失列表:"
    for m in "${missing[@]}"; do
      echo "  - $m"
    done
  fi
}

# ---------------------------------------------------------------------------
# 总结
# ---------------------------------------------------------------------------

print_summary() {
  echo ""
  echo "========================================"
  echo " 安装总结"
  echo "========================================"
  echo " 已安装: ${#SUCCEEDED[@]}"
  echo " 跳过:   ${#SKIPPED[@]}（已存在）"
  echo " 失败:   ${#FAILED[@]}"
  if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo " 失败的软件包:"
    for f in "${FAILED[@]}"; do
      echo "   - $f"
    done
  fi
  echo "========================================"
  if [ -n "${LOG_FILE:-}" ]; then
    echo " 完整日志: $LOG_FILE"
    echo "========================================"
  fi
}

# ---------------------------------------------------------------------------
# 主程序
# ---------------------------------------------------------------------------

# 为安装模式设置日志记录（非 verify/manual/dry-run）
if [ "$DRY_RUN" = false ] && [ "$MODE" != "--verify" ] && [ "$MODE" != "manual" ]; then
  setup_logging
fi

case "$MODE" in
  python) install_python; print_summary ;;
  apt) install_apt; print_summary ;;
  brew) install_brew; print_summary ;;
  gems) install_gems; print_summary ;;
  go) install_go; print_summary ;;
  manual) print_manual ;;
  --verify) verify ;;
  all)
    install_python
    if command -v apt-get >/dev/null 2>&1; then
      install_apt
    elif command -v brew >/dev/null 2>&1; then
      install_brew
    else
      log_warn "跳过操作系统包安装：未找到 apt 或 brew。"
    fi
    install_gems
    install_go
    print_manual
    print_summary
    ;;
  *)
    log_error "未知模式: $MODE"
    echo "用法: $0 [--dry-run] [--force] {python|apt|brew|gems|go|manual|all|--verify}" >&2
    exit 2
    ;;
esac

# 如果有任何软件包安装失败，则以失败状态退出
if [ ${#FAILED[@]} -gt 0 ]; then
  exit 1
fi
