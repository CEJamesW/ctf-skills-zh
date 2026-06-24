#!/usr/bin/env python3
"""Skill Security Auditor — 扫描技能目录中的安全风险。"""

import argparse
import json
import re
import sys
from pathlib import Path

# --- 模式定义 ---

CRITICAL_PATTERNS = [
    (r"rm\s+-rf\s+/", "Destructive command: rm -rf /"),
    (r"curl\s+[^\|]*\|\s*(ba)?sh", "Pipe to shell: curl | sh"),
    (r"wget\s+[^\|]*\|\s*(ba)?sh", "Pipe to shell: wget | sh"),
    (r"mkfs\.\w+\s+/dev/", "Destructive command: mkfs on device"),
    (r"dd\s+.*of=/dev/(sd|hd|vd|nvme)", "Destructive command: dd to disk device"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb"),
]

SECRET_PATTERNS = [
    (r"\b(AKIA[0-9A-Z]{16})\b", "Hardcoded AWS access key"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Embedded private key"),
    (r"\b(ghp_[A-Za-z0-9_]{36,})\b", "Hardcoded GitHub personal access token"),
    (r"\b(sk-[A-Za-z0-9]{20,})\b", "Hardcoded API key (sk-...)"),
]

HIGH_PATTERNS = [
    (r'(?<![\w.])eval\s*\(\s*["\']', "Direct eval() of string literal"),
    (r'(?<![\w.])exec\s*\(\s*["\']', "Direct exec() of string literal"),
    (r'os\.system\s*\(\s*f["\']', "os.system() with f-string (injection risk)"),
    (
        r"<script[^>]*>.*document\.(cookie|location)",
        "XSS payload accessing sensitive DOM",
    ),
    (r"chmod\s+[47]77\s+/", "World-writable permissions on system path"),
    (r"--no-check-certificate", "SSL verification disabled"),
    (r"verify\s*=\s*False", "SSL verification disabled in Python"),
]

INFO_PATTERNS = [
    (r"\b(TODO|FIXME|HACK)\s*:", "Code annotation found"),
]

PLACEHOLDER_HOST_MARKERS = (
    "exfil.com",
    "attacker.com",
    "example.com",
    "example.org",
    "example.invalid",
)

# 内联抑制：包含此标记的行将跳过HIGH级别模式检测
AUDIT_SUPPRESS_MARKER = "<!-- audit-ok"

# CTF文档模式，预期出现在攻击技术引用中。
# 这些通常出现在代码块中作为复制粘贴的payload，而非针对真实系统执行的危险命令。

# AngularJS $eval() 是模板沙箱逃逸payload，不是Python/JS的eval()
CTF_EVAL_ALLOWLIST = re.compile(
    r"\$eval\s*\("  # AngularJS $eval('...')
    r"|"
    r'eval\s*\(\s*["\']x='  # AngularJS沙箱：eval('x=alert(1)')
)

# CTF漏洞演示中常用的RCE验证命令
CTF_EXEC_ALLOWLIST = re.compile(
    r"""exec\s*\(\s*['"](?:id|ls|cat |whoami|uname|pwd|echo )"""
)

# /tmp/ 目录默认全局可写；chmod 777 /tmp/* 是内核利用
# （modprobe_path, core_pattern）中的标准操作，不构成系统风险。
CTF_CHMOD_ALLOWLIST = re.compile(r"chmod\s+[47]77\s+/tmp/")

# 各编程语言中使用的注释前缀。代码块内以这些前缀开头的行
# 是文档注释，不是可执行代码；HIGH 级别模式不应触发，但
# CRITICAL 和 SECRET 模式仍然适用。
# 涵盖 Python/Ruby/Bash/Perl (#)，JS/TS/Java/C/Go/Rust/PHP (//)，
# SQL/Lua/Haskell (--)，以及 ASM (;)
CODE_COMMENT_PREFIXES = ("#", "//", "--", ";")


FRONTMATTER_CHECKS = {
    "license": "Missing license field in frontmatter",
    "allowed-tools": "Missing allowed-tools field in frontmatter",
    "name": "Missing name field in frontmatter",
    "description": "Missing description field in frontmatter",
}

THIRD_PERSON_STARTERS = (
    "provides",
    "generates",
    "solves",
    "analyzes",
    "extracts",
    "scans",
    "detects",
    "identifies",
    "builds",
    "creates",
    "parses",
    "runs",
    "executes",
    "processes",
    "transforms",
    "validates",
    "checks",
    "orchestrates",
    "delegates",
    "implements",
)

CHINESE_THIRD_PERSON_STARTERS = (
    "提供",
    "生成",
    "解决",
    "分析",
    "提取",
    "扫描",
    "检测",
    "识别",
    "构建",
    "创建",
    "解析",
    "运行",
    "执行",
    "处理",
    "转换",
    "验证",
    "检查",
    "编排",
    "委派",
    "实现",
)


def parse_frontmatter(content: str) -> dict:
    """提取YAML frontmatter字段（简单的key: value解析）。"""
    fm = {}
    if not content.startswith("---"):
        return fm

    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", content, re.DOTALL)
    if not match:
        return fm

    block = match.group(1)
    for line in block.strip().splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            fm[key.strip()] = val.strip()
    return fm


def has_shell_true_subprocess_call(line: str) -> bool:
    """检测subprocess.call()中是否使用shell=True。"""
    if "subprocess.call" not in line or "shell=True" not in line:
        return False

    match = re.search(r'subprocess\.call\s*\(\s*([\'"])', line)
    return match is not None


# 除Markdown外还扫描的文件扩展名。脚本文件视为完全可执行代码（不跟踪代码块）。
SCRIPT_EXTENSIONS = (".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl")


def read_text_file(filepath: Path) -> tuple[str | None, dict | None]:
    """严格以UTF-8编码读取文本文件。"""
    try:
        return filepath.read_text(encoding="utf-8"), None
    except UnicodeDecodeError as e:
        return None, {
            "severity": "HIGH",
            "file": str(filepath),
            "line": 0,
            "rule": "unreadable_file",
            "message": f"无法以UTF-8解码文件: {e}",
        }
    except OSError as e:
        return None, {
            "severity": "HIGH",
            "file": str(filepath),
            "line": 0,
            "rule": "unreadable_file",
            "message": f"无法读取文件: {e}",
        }


def is_placeholder_xss_example(line: str) -> bool:
    """忽略仅使用占位符主机的教育性XSS数据外泄示例。"""
    lowered = line.lower()
    touches_sensitive_dom = (
        "document.cookie" in lowered or "document.location" in lowered
    )
    uses_placeholder_host = any(
        marker in lowered for marker in PLACEHOLDER_HOST_MARKERS
    )
    return touches_sensitive_dom and uses_placeholder_host


def scan_file(filepath: Path) -> list:
    """扫描单个文件并返回发现结果。"""
    findings = []
    content, read_error = read_text_file(filepath)
    if read_error is not None:
        findings.append(read_error)
        return findings

    is_markdown = filepath.suffix.lower() == ".md"
    lines = content.splitlines()

    # 对Markdown文件：跟踪```代码块。对脚本文件：整个文件视为可执行代码。
    in_code_block = not is_markdown
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        is_indented_code = is_markdown and (
            line.startswith("    ") or line.startswith("\t")
        )

        if is_markdown and stripped.startswith("```"):
            in_code_block = not in_code_block
            continue

        in_executable_example = in_code_block or is_indented_code

        # 代码块内的注释行是文档，不是可执行代码。
        # 以 #, //, --, ; 开头的行几乎是所有CTF技能文件中使用的注释。
        is_code_comment = (
            in_code_block
            and stripped != ""
            and any(stripped.startswith(p) for p in CODE_COMMENT_PREFIXES)
        )
        # 破坏性命令应在可执行示例中出现后再标记。
        if in_executable_example:
            for pattern, message in CRITICAL_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        {
                            "severity": "CRITICAL",
                            "file": str(filepath),
                            "line": i,
                            "rule": pattern[:40],
                            "message": message,
                            "context": line.strip()[:120],
                        }
                    )

        # 真实的秘密材料无论出现在哪里都应被标记。
        for pattern, message in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "file": str(filepath),
                        "line": i,
                        "rule": pattern[:40],
                        "message": message,
                        "context": line.strip()[:120],
                    }
                )

        # 高风险模式 — 仅在可执行代码示例中，跳过注释行
        if in_executable_example and not is_code_comment:
            # 行内抑制：当前行或上一行包含 <!-- audit-ok -->
            suppress_marker_here = AUDIT_SUPPRESS_MARKER in line
            suppress_marker_prev = i >= 2 and AUDIT_SUPPRESS_MARKER in lines[i - 2]
            suppress = suppress_marker_here or suppress_marker_prev

            if not suppress and has_shell_true_subprocess_call(line):
                findings.append(
                    {
                        "severity": "HIGH",
                        "file": str(filepath),
                        "line": i,
                        "rule": "subprocess.call+shell=True",
                        "message": "subprocess 使用 shell=True 且参数为字符串",
                        "context": line.strip()[:120],
                    }
                )

            if not suppress:
                for pattern, message in HIGH_PATTERNS:
                    if re.search(pattern, line):
                        if (
                            message == "XSS payload accessing sensitive DOM"
                            and is_placeholder_xss_example(line)
                        ):
                            continue
                        # CTF 特定的允许列表，用于已记录的攻击 payload
                        if "eval()" in message and CTF_EVAL_ALLOWLIST.search(line):
                            continue
                        if "exec()" in message and CTF_EXEC_ALLOWLIST.search(line):
                            continue
                        if "World-writable" in message and CTF_CHMOD_ALLOWLIST.search(
                            line
                        ):
                            continue
                        findings.append(
                            {
                                "severity": "HIGH",
                                "file": str(filepath),
                                "line": i,
                                "rule": pattern[:40],
                                "message": message,
                                "context": line.strip()[:120],
                            }
                        )

        for pattern, message in INFO_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    {
                        "severity": "INFO",
                        "file": str(filepath),
                        "line": i,
                        "rule": pattern[:40],
                        "message": message,
                        "context": line.strip()[:120],
                    }
                )

    return findings


def scan_skill(skill_dir: Path) -> dict:
    """扫描整个 skill 目录。"""
    findings = []

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        findings.append(
            {
                "severity": "HIGH",
                "file": str(skill_md),
                "line": 0,
                "rule": "missing_skill_md",
                "message": "skill 目录中未找到 SKILL.md",
            }
        )
    else:
        try:
            content = skill_md.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            findings.append(
                {
                    "severity": "HIGH",
                    "file": str(skill_md),
                    "line": 0,
                    "rule": "unreadable_skill_md",
                    "message": f"无法以 UTF-8 解码 SKILL.md: {e}",
                }
            )
            content = None
        except OSError as e:
            findings.append(
                {
                    "severity": "HIGH",
                    "file": str(skill_md),
                    "line": 0,
                    "rule": "unreadable_skill_md",
                    "message": f"无法读取 SKILL.md: {e}",
                }
            )
            content = None

        if content is not None:
            fm = parse_frontmatter(content)
            for key, message in FRONTMATTER_CHECKS.items():
                if key not in fm:
                    findings.append(
                        {
                            "severity": "INFO",
                            "file": str(skill_md),
                            "line": 0,
                            "rule": f"missing_{key}",
                            "message": message,
                        }
                    )

            # 验证 name 是否与目录名匹配
            if "name" in fm:
                expected_name = skill_dir.name
                actual_name = fm["name"].strip('"').strip("'")
                if actual_name != expected_name:
                    findings.append(
                        {
                            "severity": "HIGH",
                            "file": str(skill_md),
                            "line": 0,
                            "rule": "name_mismatch",
                            "message": (
                                f'Frontmatter 中的 name "{actual_name}" '
                                f'与目录名 "{expected_name}" 不匹配'
                            ),
                        }
                    )

            # 验证 description 是否为第三人称
            if "description" in fm:
                desc = fm["description"].strip('"').strip("'").strip()
                first_word = desc.split()[0].lower() if desc else ""
                chinese_third_person = any(
                    desc.startswith(starter)
                    for starter in CHINESE_THIRD_PERSON_STARTERS
                )
                description_is_third_person = (
                    first_word.endswith("s") or chinese_third_person
                )
                if first_word and not description_is_third_person:
                    findings.append(
                        {
                            "severity": "INFO",
                            "file": str(skill_md),
                            "line": 0,
                            "rule": "description_not_third_person",
                            "message": (
                                f"描述应以第三人称动词开头（例如，“Provides...”），"
                                f'但得到的是 "{first_word.capitalize()}..."'
                            ),
                        }
                    )

    # 扫描 Markdown 及其捆绑的脚本。脚本资源是隐藏真实
    # 秘密/危险调用的地方；仅扫描 Markdown 会遗漏它们。
    scan_targets: set[Path] = set(skill_dir.rglob("*.md"))
    for ext in SCRIPT_EXTENSIONS:
        scan_targets.update(skill_dir.rglob(f"*{ext}"))
    for target in sorted(scan_targets):
        findings.extend(scan_file(target))

    # 确定判定结果
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    info = sum(1 for f in findings if f["severity"] == "INFO")

    if crit > 0:
        verdict = "FAIL"
    elif high > 0:
        verdict = "WARN"
    else:
        verdict = "PASS"

    return {
        "skill": str(skill_dir),
        "verdict": verdict,
        "summary": {
            "critical": crit,
            "high": high,
            "info": info,
            "total": crit + high + info,
        },
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="技能安全审计器")
    parser.add_argument("skill_dir", help="要审计的技能目录路径")
    parser.add_argument(
        "--strict", action="store_true", help="在发现 CRITICAL 问题时以非零状态退出"
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="以 JSON 格式输出结果"
    )
    args = parser.parse_args()

    skill_path = Path(args.skill_dir)
    if not skill_path.is_dir():
        print(f"错误：{args.skill_dir} 不是一个目录", file=sys.stderr)
        sys.exit(2)

    result = scan_skill(skill_path)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        s = result["summary"]
        print(f"技能：{result['skill']}")
        print(f"判定结果：{v}")
        print(f"严重：{s['critical']}  高：{s['high']}  信息：{s['info']}")
        if result["findings"]:
            print("\n发现：")
            for f in result["findings"]:
                print(f"  [{f['severity']}] {f['file']}:{f['line']} — {f['message']}")
                if "context" in f:
                    print(f"    > {f['context']}")

    if args.strict and result["verdict"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
