"""验证CTF技能之间的交叉引用。

测试内容：
1. 每个类别中的每个技术.md文件都应在其SKILL.md中被引用
2. 所有SKILL.md文件中的/ctf-*交叉引用都应指向有效目标
3. 内部markdown链接（[text](file.md)）应解析到存在的文件
4. 文件内的锚点链接应解析到实际的标题
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# 包含技能的目录
SKILL_DIRS = sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


def _slugify_heading(heading: str) -> str:
    """将markdown标题转换为GitHub风格的锚点slug。

    这是对GitHub算法的近似。它处理本仓库中的常见情况，
    但对于表情符号、非拉丁文字或不寻常的连续特殊字符可能有所偏差。
    """
    slug = heading.lower().strip()
    # 移除markdown格式（但保留下划线——GitHub在标题锚点中保留它们，
    # 它们在像`__dict__`或`stub_execveat`这样的标识符内联代码中很常见）。
    slug = re.sub(r"[*`~]", "", slug)
    # 移除HTML标签
    slug = re.sub(r"<[^>]+>", "", slug)
    # GitHub会剥离非字母数字字符（除空格、连字符、下划线外）
    # 不会合并相邻空白——所以`A + B`变成`a--b`
    # 因为`+`被移除，且两边的空格都变成了连字符。
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = slug.replace(" ", "-")
    return slug


def _strip_fenced_code(text: str) -> str:
    """移除```...```围栏代码块（保持内联反引号内容不变，
    这样像`## `stub_execveat` Syscall`这样的标题仍会生成包含`stub_execveat`的slug）。
    """
    out_lines = []
    in_fence = False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out_lines.append("")
            continue
        out_lines.append("" if in_fence else line)
    return "\n".join(out_lines)


def _strip_all_code(text: str) -> str:
    """移除围栏代码块和内联反引号代码。用于提取markdown链接之前，
    以避免代码示例中的`obj['k']('a')`被误识别为`[k](a)`格式的链接。
    """
    text = _strip_fenced_code(text)
    return re.sub(r"`[^`]*`", "", text)


def _extract_headings(text: str) -> set[str]:
    """提取所有markdown标题为GitHub风格的锚点slug集合。"""
    headings = set()
    for m in re.finditer(r"^#{1,6}\s+(.+)$", _strip_fenced_code(text), re.MULTILINE):
        headings.add(_slugify_heading(m.group(1)))
    return headings


def _extract_skill_references(text: str) -> list[str]:
    """从文本中提取/ctf-*技能引用。"""
    return re.findall(r"/ctf-[\w-]+", text)


def _extract_local_md_links(text: str, source_dir: Path) -> list[tuple[str, str | None]]:
    """提取本地markdown链接，返回(file, anchor_or_None)元组列表。

    仅返回同目录下的.md文件链接（不包括URL）。
    先移除代码块和内联代码，避免JavaScript、Python和LaTeX示例中
    含有`[key](val)`格式语法被误识别为markdown链接。
    """
    text = _strip_all_code(text)
    links = []
    for m in re.finditer(r"\[([^\]]*)\]\(([^)]+)\)", text):
        target = m.group(2)
        # 跳过URL
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        # 跳过仓库外的绝对路径
        if target.startswith("/") and not target.startswith("/ctf-"):
            continue
        # 解析file#anchor
        if "#" in target:
            file_part, anchor = target.split("#", 1)
        else:
            file_part, anchor = target, None
        # 只检查.md文件
        if file_part and file_part.endswith(".md"):
            links.append((file_part, anchor))
    return links


class TestTechniqueFilesReferenced(unittest.TestCase):
    """技能目录中的每个.md文件都应在SKILL.md中被引用。"""

    def test_all_technique_files_referenced_in_skill_md(self):
        for skill_dir in SKILL_DIRS:
            skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            technique_files = sorted(
                f.name for f in skill_dir.glob("*.md") if f.name != "SKILL.md"
            )
            for technique in technique_files:
                with self.subTest(skill=skill_dir.name, technique=technique):
                    self.assertIn(
                        technique,
                        skill_text,
                        f"{skill_dir.name}/SKILL.md 未引用 {technique}",
                    )


class TestCrossSkillReferences(unittest.TestCase):
    """所有/ctf-*引用应指向有效的技能目录。"""

    def test_skill_references_are_valid(self):
        valid_dirs = {d.name for d in SKILL_DIRS}
        for skill_dir in SKILL_DIRS:
            skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            refs = _extract_skill_references(skill_text)
            for ref in refs:
                # /ctf-web -> ctf-web
                target = ref.lstrip("/")
                with self.subTest(skill=skill_dir.name, ref=ref):
                    self.assertIn(
                        target,
                        valid_dirs,
                        f"{skill_dir.name}/SKILL.md 引用了 {ref} "
                        f"但不存在 {target}/ 目录",
                    )


class TestLocalMarkdownLinks(unittest.TestCase):
    """本地.md文件的markdown链接应解析到存在的文件。"""

    def test_local_links_resolve(self):
        for skill_dir in SKILL_DIRS:
            for md_file in skill_dir.glob("*.md"):
                text = md_file.read_text(encoding="utf-8")
                links = _extract_local_md_links(text, skill_dir)
                for file_part, _anchor in links:
                    target_path = skill_dir / file_part
                    with self.subTest(
                        source=f"{skill_dir.name}/{md_file.name}",
                        link=file_part,
                    ):
                        self.assertTrue(
                            target_path.exists(),
                            f"{skill_dir.name}/{md_file.name} 链接到 "
                            f"{file_part}，但该文件不存在",
                        )


class TestAnchorLinks(unittest.TestCase):
    """文件内的锚点链接应解析到实际的标题。"""

    def test_same_file_anchors_resolve(self):
        for skill_dir in SKILL_DIRS:
            for md_file in skill_dir.glob("*.md"):
                text = md_file.read_text(encoding="utf-8")
                headings = _extract_headings(text)
                links = _extract_local_md_links(text, skill_dir)
                for file_part, anchor in links:
                    if anchor is None:
                        continue
                    # 对于指向其他文件的链接，检查该文件的标题
                    if file_part:
                        target_path = skill_dir / file_part
                        if not target_path.exists():
                            continue  # 由 TestLocalMarkdownLinks 覆盖
                        target_text = target_path.read_text(encoding="utf-8")
                        target_headings = _extract_headings(target_text)
                    else:
                        target_headings = headings

                    with self.subTest(
                        source=f"{skill_dir.name}/{md_file.name}",
                        anchor=anchor,
                    ):
                        self.assertIn(
                            anchor,
                            target_headings,
                            f"{skill_dir.name}/{md_file.name} 链接到 "
                            f"#{anchor} 但在 "
                            f"{file_part or md_file.name} 中未找到该标题",
                        )


class TestBidirectionalPivotReferences(unittest.TestCase):
    """如果技能 A 在 When to Pivot 中提到 /ctf-B，B 应该提到 /ctf-A。"""

    def _extract_pivot_targets(self, text: str) -> set[str]:
        """从 'When to Pivot' 部分提取 /ctf-* 目标。"""
        lines = text.splitlines()
        in_pivot = False
        targets = set()
        for line in lines:
            if re.match(r"^##\s+When to Pivot", line):
                in_pivot = True
                continue
            if in_pivot and re.match(r"^##\s+", line):
                break
            if in_pivot:
                for ref in _extract_skill_references(line):
                    targets.add(ref.lstrip("/"))
        return targets

    def test_pivot_references_are_bidirectional(self):
        pivot_map: dict[str, set[str]] = {}
        for skill_dir in SKILL_DIRS:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            targets = self._extract_pivot_targets(text)
            if targets:
                pivot_map[skill_dir.name] = targets

        for source, targets in pivot_map.items():
            for target in targets:
                with self.subTest(source=source, target=target):
                    if target not in pivot_map:
                        # 目标技能没有 pivot 部分 — 不是失败，
                        # 但值得注意
                        continue
                    self.assertIn(
                        source,
                        pivot_map.get(target, set()),
                        f"{target}/SKILL.md 的 'When to Pivot' 没有 "
                        f"回指 /{source} "
                        f"(但 {source} 引用了 /{target})。"
                        f"修复方法：在 {target}/SKILL.md 的 'When to Pivot' 部分添加 "
                        f"'- 如果 ..., 切换到 `/{source}`.' 项。",
                    )
