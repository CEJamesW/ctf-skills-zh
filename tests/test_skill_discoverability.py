"""验证核心 CTF 技能是否仍能从现实提示中被发现。

此测试故意设计得较轻量：仅使用 SKILL.md frontmatter
描述加上一个小的同义词映射来模拟初步路由。
如果未来的编辑使描述变得模糊，这些用例应在回归影响真实挑战解决会话之前失败。
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CORE_SKILLS = {
    "ctf-web",
    "ctf-pwn",
    "ctf-reverse",
    "ctf-misc",
    "solve-challenge",
}

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "be",
    "before",
    "but",
    "by",
    "category",
    "categories",
    "challenge",
    "challenges",
    "clear",
    "core",
    "ctf",
    "do",
    "dominant",
    "family",
    "first",
    "for",
    "from",
    "genuine",
    "gives",
    "how",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "know",
    "main",
    "must",
    "need",
    "not",
    "of",
    "on",
    "or",
    "out",
    "performing",
    "point",
    "primarily",
    "problems",
    "provides",
    "real",
    "right",
    "skill",
    "solve",
    "solves",
    "specialized",
    "start",
    "still",
    "such",
    "target",
    "that",
    "the",
    "their",
    "them",
    "then",
    "this",
    "to",
    "use",
    "user",
    "vague",
    "we",
    "when",
    "where",
    "which",
    "with",
    "you",
}

TOKEN_ALIASES = {
    "http": {"http", "https", "web", "website", "browser", "endpoint", "api"},
    "xss": {"xss", "dom", "cookie", "adminbot", "admin", "bot"},
    "sqli": {"sqli", "sql", "database", "union", "blind"},
    "ssti": {"ssti", "template", "jinja2", "twig", "erb"},
    "jwt": {"jwt", "jwe", "token", "jwks", "oauth", "oidc", "saml"},
    "upload": {"upload", "multipart", "polyglot"},
    "buffer": {"overflow", "buffer", "smash"},
    "format": {"format", "printf"},
    "heap": {"heap", "tcache", "uaf", "unlink"},
    "rop": {"rop", "ret2libc", "gadget", "shellcode", "seccomp"},
    "kernel": {"kernel", "kaslr", "slub"},
    "binary": {"binary", "elf", "executable"},
    "obfuscated": {"obfuscated", "packed", "virtualized", "vm", "bytecode"},
    "firmware": {"firmware", "apk", "wasm", "loader"},
    "reverse": {"reverse", "ghidra", "ida", "decompile", "stripped", "protocol"},
    "pyjails": {"pyjail", "python", "jail", "sandbox"},
    "audio": {"audio", "spectrogram", "dtmf", "wav"},
    "qr": {"qr", "barcode"},
    "unicode": {"unicode", "encoding", "esoteric"},
    "dns": {"dns", "zone"},
    "challenge": {"challenge", "bundle", "zip", "pcap", "service", "remote", "nc"},
    "vague": {"unknown", "unsure", "mystery", "suspicious"},
}

CHINESE_TOKEN_ALIASES = {
    "http": ("网站", "网页", "接口", "浏览器", "管理面板"),
    "xss": ("管理员机器人", "机器人", "cookie", "会话"),
    "ssti": ("模板", "渲染"),
    "jwt": ("令牌", "重定向"),
    "buffer": ("缓冲区", "溢出", "栈控制"),
    "format": ("格式化字符串",),
    "heap": ("堆", "uaf", "tcache"),
    "rop": ("rop", "ret2libc", "gadget", "shellcode", "libc"),
    "binary": ("二进制", "可执行文件", "elf"),
    "obfuscated": ("混淆", "加壳", "剥壳", "虚拟机", "字节码"),
    "reverse": ("逆向", "反调试", "恢复协议", "理解可执行文件"),
    "pyjails": ("沙箱",),
    "qr": ("二维码",),
    "unicode": ("unicode",),
    "challenge": ("挑战", "压缩包", "远程", "服务", "nc"),
    "vague": ("不知道类别", "还不知道", "弄清楚", "从哪里开始"),
}


def _parse_frontmatter(text: str) -> dict[str, str] | None:
    """解析 SKILL.md 文件使用的扁平 frontmatter 风格。"""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None

    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return None

    result: dict[str, str] = {}
    current_block: str | None = None
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            current_block = stripped[:-1]
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"')
        if current_block:
            result[f"{current_block}.{key}"] = value
        else:
            result[key] = value
    return result


def _tokenize(text: str) -> set[str]:
    """对文本进行分词并扩展常见的 CTF 同义词。"""
    lowered = text.lower()
    raw_tokens = set(re.findall(r"[a-z0-9_./+-]+", lowered))
    base_tokens = {
        token
        for token in raw_tokens
        if len(token) >= 3 and token not in STOPWORDS
    }
    expanded = set(base_tokens)
    for canonical, variants in TOKEN_ALIASES.items():
        if base_tokens & variants:
            expanded.add(canonical)
            expanded.update(variants)
    for canonical, phrases in CHINESE_TOKEN_ALIASES.items():
        if any(phrase in lowered for phrase in phrases):
            expanded.add(canonical)
            expanded.update(TOKEN_ALIASES.get(canonical, ()))
    return expanded


def _load_descriptions() -> dict[str, dict[str, set[str]]]:
    """从每个核心技能描述中加载正面和负面词汇。"""
    descriptions: dict[str, dict[str, set[str]]] = {}
    for skill_dir in sorted(REPO_ROOT.glob("*/SKILL.md")):
        name = skill_dir.parent.name
        if name not in CORE_SKILLS:
            continue
        text = skill_dir.read_text(encoding="utf-8")
        fm = _parse_frontmatter(text)
        if fm is None:
            continue
        desc = fm["description"]
        positive_text, _, negative_text = desc.partition("Do not use")
        descriptions[name] = {
            "positive": _tokenize(positive_text),
            "negative": _tokenize(negative_text),
        }
    return descriptions


def _recommend_skill(prompt: str, descriptions: dict[str, dict[str, set[str]]]) -> str:
    """根据提示推荐最匹配的技能。"""
    prompt_tokens = _tokenize(prompt)
    best_skill = ""
    best_score = -10**9
    strong_specific = {"xss", "sqli", "ssti", "jwt", "buffer", "heap", "rop", "reverse", "pyjails"}

    for skill, buckets in descriptions.items():
        positive_hits = len(prompt_tokens & buckets["positive"])
        negative_hits = len(prompt_tokens & buckets["negative"])
        score = positive_hits * 3 - negative_hits * 4

        if skill == "ctf-misc":
            if {"pyjails", "audio", "qr", "unicode", "dns"} & prompt_tokens:
                score += 8
            else:
                score -= 8

        # 仅当提示非常模糊时才偏好调度器。
        if skill == "solve-challenge":
            if {"challenge", "bundle", "zip"} & prompt_tokens:
                score += 2
            if {"unknown", "unsure", "mystery", "suspicious", "vague"} & prompt_tokens:
                score += 5
            if strong_specific & prompt_tokens:
                score -= 8

        if score > best_score:
            best_skill = skill
            best_score = score

    return best_skill


class TestSkillDiscoverability(unittest.TestCase):
    """核心路由描述应仍能区分主要的 CTF 分类。"""

    @classmethod
    def setUpClass(cls):
        cls.descriptions = _load_descriptions()
        missing = CORE_SKILLS - cls.descriptions.keys()
        if missing:
            raise AssertionError(f"缺少以下描述: {sorted(missing)}")

    def test_core_skills_win_expected_scenarios(self):
        cases = [
            (
                "ctf-web",
                "目标是一个使用 Flask 的网站，带有 JWT cookies、上传表单和一个渲染 HTML 的管理员机器人。我们已经看到 SSTI 和可能的 XSS。",
            ),
            (
                "ctf-pwn",
                "我们已经确认了一个 ELF 服务中的堆 UAF，获得了 libc 泄露，需要进行 tcache 污染加 ROP 链来获取 shell。",
            ),
            (
                "ctf-reverse",
                "该挑战提供了一个带有自定义虚拟机和混淆字节码的剥壳二进制文件。阻碍点是在利用前理解可执行文件的功能。",
            ),
            (
                "ctf-misc",
                "该服务是一个带有奇怪 Unicode 过滤和二维码线索的 Python 沙箱。看起来更像是一个混合沙箱谜题，而非网页或二进制利用。",
            ),
            (
                "solve-challenge",
                "这里有一个来自 CTF 的压缩包和一个远程 nc 服务。我还不知道类别，需要弄清楚从哪里开始。",
            ),
        ]

        for expected, prompt in cases:
            with self.subTest(expected=expected, prompt=prompt):
                actual = _recommend_skill(prompt, self.descriptions)
                self.assertEqual(actual, expected)

    def test_boundary_between_reverse_and_pwn(self):
        cases = [
            (
                "ctf-reverse",
                "我们有一个带有反调试技巧且无已知漏洞的加壳 ELF。首先需要逆向二进制并恢复协议。",
            ),
            (
                "ctf-pwn",
                "我们已经知道漏洞是本地服务中的格式化字符串。剩下的任务是栈控制、libc 泄露和 ret2libc 利用。",
            ),
        ]

        for expected, prompt in cases:
            with self.subTest(expected=expected, prompt=prompt):
                actual = _recommend_skill(prompt, self.descriptions)
                self.assertEqual(actual, expected)

    def test_misc_is_fallback_not_default(self):
        prompt = (
            "该网站暴露了 OAuth 重定向、JWT 会话和浏览器管理面板。"
            "感觉不寻常，但核心漏洞类别仍然是 web。"
        )
        actual = _recommend_skill(prompt, self.descriptions)
        self.assertEqual(actual, "ctf-web")


if __name__ == "__main__":
    unittest.main()
