# 贡献指南：ctf-skills

感谢你帮助扩展 CTF 技能集合。本指南涵盖如何设置开发环境、添加技术、创建新的技能类别以及合并你的 PR。

## 开发环境设置

### 前置条件

- Python 3.12 及以上
- Node.js（用于 markdownlint）
- [pre-commit](https://pre-commit.com/)

### 安装 pre-commit 钩子

```bash
pip install pre-commit
pre-commit install
```

这会安装在每次提交时自动运行的钩子：

- **trailing-whitespace** 和 **end-of-file-fixer** — 基础格式修正
- **check-yaml** — 验证 YAML 文件
- **check-added-large-files** — 防止意外提交大文件（如二进制）
- **ruff** — Python 代码检查和格式化（针对 `scripts/` 目录下文件）
- **shellcheck** — Shell 脚本静态分析
- **markdownlint-cli2** — Markdown 代码风格检查（所有 `.md` 文件）

### 安装测试依赖

```bash
pip install pytest
```

## 向已有技能添加技术

这是最常见的贡献方式。每个技能类别（如 `ctf-web`、`ctf-crypto`）包含一个 `SKILL.md` 文件和一个或多个支持的技术文件。

### 1. 选择合适的文件

查看技能目录下已有的技术文件。例如，`ctf-web/` 目录下有 `sql-injection.md`、`server-side.md`、`client-side.md` 等文件。将你的技术添加到最匹配主题的文件中。如果没有合适的文件，可以新建一个。

### 2. 遵循技术格式

技术文件采用以下结构：

````markdown
## 技术名称（可选 CTF/年份归属）

简要说明何时以及为何使用该技术。

```language
# 可用的 payload 或代码示例
# 使用真实但安全的占位目标（example.com，attacker.com）
```

**关键洞察：** 用一两句话解释核心思想。
````

约定：

- 每个技术以二级标题（`##`）开头
- 在带语言标记的代码块中包含可用的代码示例
- 使用占位主机名（`example.com`、`attacker.com`）——绝不使用真实基础设施
- 如果已知，标题中注明来源 CTF/竞赛
- 说明简洁明了——这是快速参考，不是教程

### 3. 更新 SKILL.md

添加技术后，更新父级 `SKILL.md`：

- 如果修改了已有文件，将技术添加到 **Additional Resources** 列表
- 如果新建了技术文件，新增一条相对链接的条目

### 4. 更新 README 表格

更新 `README.md` 中对应技能的行：如果添加了新文件，增加 **Files** 计数，并在 **Description** 列添加技术名称。

## 创建新的技能类别

新的技能类别是在仓库根目录下的一个目录，至少包含一个 `SKILL.md` 文件。

`SKILL.md` 必须包含带有以下必填字段的 YAML frontmatter：

```yaml
---
name: ctf-newcategory
description: >-
  提供 CTF 挑战的 [category] 技术。适用于 [触发条件]。
license: MIT
compatibility: 需要基于文件系统的代理（如 Claude Code 或类似工具），支持 bash、Python 3，并能联网安装工具。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---
```

frontmatter 规则由测试强制执行：

| 字段 | 要求 |
|-------|-------------|
| `name` | 必须与目录名完全匹配 |
| `description` | 长度超过 20 个字符；必须以第三人称动词开头（如“提供...”、“解决...”） |
| `license` | 必须是 `MIT` |
| `compatibility` | 必填，自由格式字符串 |
| `allowed-tools` | 空格分隔列表；有效值：`Bash`、`Read`、`Write`、`Edit`、`Glob`、`Grep`、`Task`、`WebFetch`、`WebSearch`、`Skill` |
| `metadata.user-invocable` | 必须是 `"true"` 或 `"false"` |
| `metadata.argument-hint` | 如果 `user-invocable` 是 `"true"`，则必填 |

## 本地运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 仅运行 frontmatter 验证
python -m pytest tests/test_skill_frontmatter.py -v

# 对特定技能运行安全审计
python3 scripts/skill_security_auditor.py ctf-web --strict --json
```

### 手动运行 pre-commit 检查

```bash
pre-commit run --all-files
```

## 代码质量标准

- **Markdown** — 由 markdownlint-cli2 检查（针对 CTF 内容放宽规则，配置在 `.markdownlint-cli2.yaml`）
- **Python/Shell** — `scripts/` 目录由 ruff 和 shellcheck 检查
- **安全** — 每个 PR 触发技能安全审计工作流。严重问题会导致构建失败。使用 `<!-- audit-ok -->` 注释抑制有意的攻击文档。
- **链接** — 链接检查器（lychee）验证所有 URL，针对每个 PR 及每周运行

## Pull Request 流程

### 提交前

1. 运行 `pre-commit run --all-files` 并修复所有问题
2. 运行 `python -m pytest tests/ -v` 并确保所有测试通过
3. 如果添加了新技能，确认 frontmatter 中的 `name` 与目录名一致

### 审核者关注点

- 代码示例可用，使用占位主机名（无真实凭据或在线基础设施）
- 技术分类正确，放在合适的技能和文件中
- frontmatter 合法且安全审计通过
- 更新了 SKILL.md 和 README 以反映更改
- 技术标题中注明已知的来源 CTF/竞赛

### 必须通过的 CI 检查

| 工作流 | 功能说明 |
|----------|--------------|
| **Tests** | 运行 `pytest` 测试 `tests/` 目录 |
| **Markdown Lint** | 对所有 `.md` 文件运行 markdownlint-cli2 |
| **Skill Security Audit** | 扫描变更的技能，检测危险模式 |
| **Link Checker** | 验证所有 `.md` 文件中的 URL |
| **Lint Scripts** | 对 `scripts/` 目录运行 ruff 和 shellcheck |

## 责任使用

本仓库记录的攻击性安全技术仅限于**授权的 CTF 竞赛、安全研究和教育用途**。所有贡献者必须遵守 [SECURITY.md](SECURITY.md) 中的责任使用政策。切勿包含真实凭据、个人信息或指向在线恶意基础设施的链接。
