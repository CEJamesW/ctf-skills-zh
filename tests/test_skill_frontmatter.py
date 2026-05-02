"""验证仓库中所有技能的 SKILL.md frontmatter。"""

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

VALID_TOOLS = {
    "Bash",
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "Task",
    "WebFetch",
    "WebSearch",
    "Skill",
}

REQUIRED_FIELDS = {"name", "description", "license", "compatibility", "allowed-tools"}


def _parse_frontmatter(text: str) -> dict[str, str] | None:
    """解析位于 --- 标记之间的 YAML frontmatter 为扁平字典。

    处理 SKILL.md 文件中使用的简单 key: value 格式，以及嵌套的 metadata 块。
    """
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

        # 检测嵌套块（例如 "metadata:"）
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


def _discover_skills() -> list[Path]:
    """查找所有包含 SKILL.md 文件的目录。"""
    return sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


class TestSkillFrontmatter(unittest.TestCase):
    """验证仓库中每个 SKILL.md 的 frontmatter。"""

    def setUp(self):
        self.skills = _discover_skills()
        self.assertGreater(len(self.skills), 0, "未找到任何 SKILL.md 文件")

    def test_all_skills_have_valid_frontmatter(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            with self.subTest(skill=skill_dir.name):
                self.assertIsNotNone(fm, f"{skill_dir.name}/SKILL.md 缺少 frontmatter")

    def test_required_fields_present(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                missing = REQUIRED_FIELDS - fm.keys()
                self.assertEqual(
                    missing,
                    set(),
                    f"{skill_dir.name}/SKILL.md 缺少字段: {missing}",
                )

    def test_name_matches_directory(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                self.assertEqual(
                    fm.get("name"),
                    skill_dir.name,
                    f"name '{fm.get('name')}' 与目录名 '{skill_dir.name}' 不匹配",
                )

    def test_allowed_tools_are_valid(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                tools_str = fm.get("allowed-tools", "")
                tools = set(tools_str.split())
                unknown = tools - VALID_TOOLS
                self.assertEqual(
                    unknown,
                    set(),
                    f"{skill_dir.name} 存在未知工具: {unknown}",
                )

    def test_license_is_mit(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                self.assertEqual(
                    fm.get("license"),
                    "MIT",
                    f"{skill_dir.name} 许可证为 '{fm.get('license')}'，预期为 'MIT'",
                )

    def test_user_invocable_is_boolean_string(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                value = fm.get("metadata.user-invocable")
                self.assertIsNotNone(
                    value,
                    f"{skill_dir.name} 缺少 metadata.user-invocable",
                )
                self.assertIn(
                    value,
                    ("true", "false"),
                    f"{skill_dir.name} metadata.user-invocable 的值为 '{value}'",
                )

    def test_invocable_skills_have_argument_hint(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                if fm.get("metadata.user-invocable") == "true":
                    hint = fm.get("metadata.argument-hint")
                    self.assertIsNotNone(
                        hint,
                        f"{skill_dir.name} 可被用户调用但缺少 argument-hint",
                    )
                    self.assertGreater(
                        len(hint),
                        0,
                        f"{skill_dir.name} 的 argument-hint 为空",
                    )

    def test_description_is_meaningful(self):
        for skill_dir in self.skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm is None:
                continue
            with self.subTest(skill=skill_dir.name):
                desc = fm.get("description", "")
                self.assertGreater(
                    len(desc),
                    20,
                    f"{skill_dir.name} 描述过短（{len(desc)} 字符）",
                )
