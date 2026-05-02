---
name: ctf-writeup
description: 生成一个标准化的提交风格 CTF writeup，便于比赛交接和组织者审核。用于解决 CTF 挑战后，以结构化格式记录解决步骤、使用的工具和经验教训。
license: MIT
compatibility: 需要基于文件系统的代理（如 Claude Code 或类似工具），支持 bash 和 Python 3。
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "[challenge-name]"
---

# CTF Write-up Generator

生成一个标准化的提交风格 CTF writeup，用于已解决的挑战。

默认行为：

- 在比赛进行中，优化速度、清晰度和可复现性
- 保持 writeup 简短，方便队友或组织者快速验证解题
- 始终生成 `submission` 风格的 writeup
- 优先提供从挑战数据到最终 flag 的完整解题脚本

## 工作流程

### 第一步：收集信息

从当前会话、挑战文件和用户输入中收集以下内容：

1. **挑战元数据** — 名称、CTF 赛事、类别、难度、分数、flag 格式
2. **解决方案产物** — 利用脚本、payload、截图、命令输出
3. **时间线** — 关键步骤、死胡同、转折点

```bash
# 扫描利用脚本和产物
find . -name '*.py' -o -name '*.sh' -o -name 'exploit*' -o -name 'solve*' | head -20
# 检查输出文件中的 flag
grep -rniE '(flag|ctf|eno|htb|pico)\{' . 2>/dev/null
```

### 第二步：生成 Write-up

使用下面的提交模板，将 writeup 文件写为 `writeup.md`（或 `writeup-<challenge-name>.md`）。

---

## 模板

### 提交格式

```markdown
---
title: "<挑战名称>"
ctf: "<CTF 赛事名称>"
date: YYYY-MM-DD
category: web|pwn|crypto|reverse|forensics|osint|malware|misc
difficulty: easy|medium|hard
points: <分数>
flag_format: "flag{...}"
author: "<你的名字或团队>"
---

# <挑战名称>

## 概述

<1-2 句简述：挑战内容及核心技术，保持简洁明了。>

## 解决方案

### 第一步：<操作>

<用 3-8 行简短说明关键观察，保持直接。>

\`\`\`python
<从提供的挑战数据到打印最终 flag 的完整解题脚本>
\`\`\`

### 第二步：<操作>（可选）

<仅当第二步有助于提升可读性时添加，例如将核心观察与最终验证分开。>

### 第三步：<操作>（可选）

<仅在挑战确实需要时使用。保持步骤总数较少。>

## Flag

\`\`\`
flag{example_flag_here}
\`\`\`
```

指导原则：

- 总步骤数优先保持在 1-3 步
- 代码保持为最小完整解题脚本
- 不要将“恢复密钥”、“推导密钥”和“解密 flag”拆分成多个片段
- 脚本应从挑战数据开始，最终打印 flag
- 避免冗长的背景介绍
- 避免死胡同，除非解释关键转折
- 避免多条备选解法，选择一条清晰路径
- 仅在用户明确要求时才遮蔽 flag

---

## 最佳实践检查清单

在完成 writeup 前，请确认：

- [ ] **元数据完整** — 标题、CTF、日期、类别、难度、分数、作者均填写
- [ ] **flag 处理符合要求** — 保留真实 flag，除非用户要求遮蔽
- [ ] **步骤可复现** — 读者能跟随 writeup 复现解题过程
- [ ] **代码可运行** — 利用脚本包含所有导入、正确变量名和注释
- [ ] **无敏感信息** — 无真实凭据、API 密钥或私有基础设施细节
- [ ] **篇幅简洁** — writeup 足够简短，便于快速审核
- [ ] **工具及版本注明** — 如行为依赖特定版本，需说明
- [ ] **适当归属** — 致谢队友、参考 writeup 或关键工具
- [ ] **语法和格式规范** — 标题层级一致，代码块带语言标记
## 质量指南

**应当：**
- 解释足够的信息以便快速验证
- 包含一条完整的解题路径，而非多条备选路线
- 包含一段完整的脚本，直至最终获取 flag
- 展示实际输出（若过长可截断），以证明方法有效
- 给代码块标注语言（如 `python`、`bash`、`sql` 等）
- 将主要路径放在前面，方便读者快速验证

**不应：**
- 直接复制粘贴未经解释的终端原始输出
- 粘贴多个片段，迫使读者自行拼凑最终解法
- 在最终写作中留下占位符文本
- 包含与解题无关的枝节内容
- 假设读者了解具体的挑战设置

## 挑战

$ARGUMENTS
