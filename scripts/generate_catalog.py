#!/usr/bin/env python3
"""为 GitHub Pages 生成静态 HTML 技能目录与各 .md 渲染页。"""

import html
import re
import shutil
import subprocess
from pathlib import Path

import markdown

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "_site"

_DEFAULT_REPO_URL = "https://github.com/CEJamesW/ctf-skills-zh"
INSTALL_CMD = "npx skills add CEJamesW/ctf-skills-zh"


def _detect_repo_url() -> str:
    try:
        url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if url.startswith("ssh://"):
            url = url.replace("ssh://", "https://", 1).replace("git@", "")
        elif url.startswith("git@"):
            url = url.replace("git@", "https://", 1).replace(":", "/", 1)
        url = url.removesuffix(".git")
        return url
    except (subprocess.CalledProcessError, FileNotFoundError):
        return _DEFAULT_REPO_URL


_repo_url: str | None = None


def _get_repo_url() -> str:
    global _repo_url
    if _repo_url is None:
        _repo_url = _detect_repo_url()
    return _repo_url


CATEGORY_COLORS = {
    "ctf-web": "#1d76db",
    "ctf-pwn": "#d93f0b",
    "ctf-crypto": "#0e8a16",
    "ctf-reverse": "#5319e7",
    "ctf-forensics": "#006b75",
    "ctf-osint": "#fbca04",
    "ctf-malware": "#b60205",
    "ctf-misc": "#c5def5",
    "ctf-ai-ml": "#f9d0c4",
    "ctf-writeup": "#888888",
    "solve-challenge": "#555555",
}

CATEGORY_ICONS = {
    "ctf-web": "\U0001f310",
    "ctf-pwn": "\U0001f4a3",
    "ctf-crypto": "\U0001f510",
    "ctf-reverse": "\U0001f50e",
    "ctf-forensics": "\U0001f50d",
    "ctf-osint": "\U0001f30e",
    "ctf-malware": "\U0001f9a0",
    "ctf-misc": "\U0001f9e9",
    "ctf-ai-ml": "\U0001f916",
    "ctf-writeup": "\U0001f4dd",
    "solve-challenge": "\U0001f3af",
}


def parse_frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return {}
    result: dict[str, str] = {}
    block: str | None = None
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            block = stripped[:-1]
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"')
        if block:
            result[f"{block}.{key}"] = value
        else:
            result[key] = value
    return result


def strip_frontmatter(text: str) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return text
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[i + 1:])
    return text


def discover_skills() -> list[Path]:
    return sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


def count_techniques(skill_dir: Path) -> list[dict[str, str]]:
    techniques = []
    for md in sorted(skill_dir.glob("*.md")):
        if md.name == "SKILL.md":
            continue
        name = md.stem.replace("-", " ").replace("_", " ").title()
        techniques.append({"name": name, "file": md.name})
    return techniques


_MD_HREF_RE = re.compile(r'(href=["\'])([^"\']+?)\.md(#[^"\']*)?(["\'])')


def _rewrite_md_links(html_text: str) -> str:
    """把 <a href="x.md"> 改成 <a href="x.html">，保留锚点。"""
    return _MD_HREF_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}.html{m.group(3) or ''}{m.group(4)}",
        html_text,
    )


PAGE_CSS = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --text-muted: #8b949e; --link: #58a6ff;
  --code-bg: #1f242c;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial,
    'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.7;
  padding: 2rem 1rem;
}
.container { max-width: 920px; margin: 0 auto; }
.topbar { margin-bottom: 1.5rem; padding-bottom: 1rem;
  border-bottom: 1px solid var(--border); display: flex; gap: 1rem;
  align-items: center; flex-wrap: wrap; }
.topbar a { color: var(--link); text-decoration: none; font-size: 0.9rem; }
.topbar a:hover { text-decoration: underline; }
.topbar .crumb-sep { color: var(--text-muted); }
article h1, article h2, article h3, article h4 {
  margin: 1.6em 0 0.6em; line-height: 1.3;
}
article h1 { font-size: 1.9rem; padding-bottom: 0.3em;
  border-bottom: 1px solid var(--border); }
article h2 { font-size: 1.5rem; padding-bottom: 0.2em;
  border-bottom: 1px solid var(--border); }
article h3 { font-size: 1.2rem; }
article p, article ul, article ol, article blockquote, article table {
  margin: 0.8em 0;
}
article ul, article ol { padding-left: 1.5em; }
article li { margin: 0.2em 0; }
article a { color: var(--link); text-decoration: none; }
article a:hover { text-decoration: underline; }
article code {
  background: var(--code-bg); padding: 0.15em 0.4em;
  border-radius: 4px; font-size: 0.92em;
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
}
article pre {
  background: var(--code-bg); padding: 1em; border-radius: 6px;
  overflow-x: auto; margin: 0.8em 0; border: 1px solid var(--border);
}
article pre code { background: transparent; padding: 0; font-size: 0.88em; }
article blockquote {
  padding: 0 1em; color: var(--text-muted);
  border-left: 0.25em solid var(--border);
}
article table { border-collapse: collapse; width: 100%; }
article th, article td {
  border: 1px solid var(--border); padding: 0.4em 0.7em; text-align: left;
}
article th { background: var(--surface); }
article img { max-width: 100%; }
article hr { border: 0; border-top: 1px solid var(--border); margin: 1.5em 0; }
footer { text-align: center; margin-top: 3rem; padding-top: 1.5rem;
  border-top: 1px solid var(--border); color: var(--text-muted);
  font-size: 0.85rem; }
footer a { color: var(--link); text-decoration: none; }
"""


def render_markdown_page(
    md_path: Path, out_path: Path, breadcrumb: list[tuple[str, str]]
) -> None:
    """把单个 .md 文件渲染成完整的 HTML 页面。"""
    text = md_path.read_text(encoding="utf-8")
    body_md = strip_frontmatter(text)
    md = markdown.Markdown(
        extensions=["fenced_code", "tables", "toc", "sane_lists"],
        output_format="html5",
    )
    body_html = md.convert(body_md)
    body_html = _rewrite_md_links(body_html)

    crumb_html = ""
    for i, (label, href) in enumerate(breadcrumb):
        if href:
            crumb_html += (
                f'<a href="{html.escape(href)}">{html.escape(label)}</a>'
            )
        else:
            crumb_html += f'<span>{html.escape(label)}</span>'
        if i < len(breadcrumb) - 1:
            crumb_html += '<span class="crumb-sep">›</span>'

    title = html.escape(md_path.stem)
    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} · CTF 技能目录</title>
  <style>{PAGE_CSS}</style>
</head>
<body>
  <div class="container">
    <nav class="topbar">{crumb_html}</nav>
    <article>{body_html}</article>
    <footer>
      <a href="{_get_repo_url()}">GitHub 仓库</a> &middot;
      <a href="{_get_repo_url()}/blob/main/{md_path.relative_to(REPO_ROOT).as_posix()}">查看源 Markdown</a>
      &middot; MIT 许可证
    </footer>
  </div>
</body>
</html>"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")


def build_index_html(skills: list[dict]) -> str:
    """生成首页技能目录。"""
    total_techniques = sum(len(s["techniques"]) for s in skills)
    total_categories = len(skills)

    cards = []
    for s in skills:
        color = CATEGORY_COLORS.get(s["dir_name"], "#666")
        icon = html.escape(CATEGORY_ICONS.get(s["dir_name"], "\U0001f4c4"))
        tech_count = len(s["techniques"])
        desc = html.escape(s.get("description", ""))
        skill_link = f"{s['dir_name']}/SKILL.html"

        if s["techniques"]:
            badge_text = (
                f"{tech_count} 篇" if tech_count != 1 else "1 篇"
            )
            items = []
            for t in s["techniques"]:
                href = f"{s['dir_name']}/{Path(t['file']).stem}.html"
                items.append(
                    f'<li><a href="{href}">{html.escape(t["name"])}</a></li>'
                )
            tech_list = f'<ul class="technique-list">{"".join(items)}</ul>'
        else:
            badge_text = "查看 SKILL"
            tech_list = (
                '<ul class="technique-list">'
                f'<li><a href="{skill_link}">查看 SKILL.md →</a></li>'
                '</ul>'
            )

        cards.append(f"""
    <div class="card" style="border-top: 4px solid {color}">
      <a class="card-link" href="{skill_link}">
        <div class="card-header">
          <span class="icon">{icon}</span>
          <h2>{html.escape(s["dir_name"])}</h2>
          <span class="badge" style="background:{color}">{badge_text}</span>
        </div>
        <p class="description">{desc}</p>
      </a>
      {tech_list}
    </div>""")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CTF 技能目录</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --text-muted: #8b949e; --link: #58a6ff;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica,
        Arial, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.6;
      padding: 2rem 1rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      text-align: center; margin-bottom: 2rem; padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }}
    header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
    header p {{ color: var(--text-muted); font-size: 1.1rem; }}
    .stats {{ display: flex; justify-content: center; gap: 2rem;
      margin-top: 1rem; }}
    .stat {{ text-align: center; padding: 0.5rem 1rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; }}
    .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
    .stat-label {{ color: var(--text-muted); font-size: 0.85rem; }}
    .install-box {{
      text-align: center; margin: 1.5rem 0; padding: 1rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .install-box code {{
      background: var(--bg); padding: 0.4rem 0.8rem; border-radius: 4px;
      font-size: 1rem; color: var(--link);
    }}
    .grid {{ display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 1.5rem; margin-top: 2rem; }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.25rem;
      transition: transform 0.15s ease;
    }}
    .card:hover {{ transform: translateY(-2px); }}
    .card-link {{ display: block; color: inherit; text-decoration: none; }}
    .card-link:hover h2 {{ color: var(--link); }}
    .card-header {{ display: flex; align-items: center; gap: 0.5rem;
      margin-bottom: 0.75rem; }}
    .card-header h2 {{ font-size: 1.1rem; flex: 1; }}
    .icon {{ font-size: 1.3rem; }}
    .badge {{ color: #fff; font-size: 0.75rem; padding: 0.15rem 0.5rem;
      border-radius: 10px; font-weight: 600; }}
    .description {{ color: var(--text-muted); font-size: 0.85rem;
      margin-bottom: 0.75rem; display: -webkit-box;
      -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }}
    .technique-list {{ list-style: none; display: flex; flex-wrap: wrap;
      gap: 0.4rem; }}
    .technique-list li {{
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 4px; padding: 0.15rem 0.5rem; font-size: 0.8rem;
    }}
    .technique-list a {{ color: var(--link); text-decoration: none; }}
    .technique-list a:hover {{ text-decoration: underline; }}
    footer {{
      text-align: center; margin-top: 3rem; padding-top: 1.5rem;
      border-top: 1px solid var(--border); color: var(--text-muted);
      font-size: 0.85rem;
    }}
    footer a {{ color: var(--link); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}
    .attribution {{ font-size: 0.8rem; color: var(--text-muted);
      max-width: 720px; margin: 0.5rem auto 0; }}
    .attribution a {{ color: var(--link); }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>CTF 技能目录</h1>
      <p>用于解决 Capture The Flag 挑战的代理技能 · 简体中文</p>
      <div class="stats">
        <div class="stat">
          <div class="stat-value">{total_categories}</div>
          <div class="stat-label">分类</div>
        </div>
        <div class="stat">
          <div class="stat-value">{total_techniques}</div>
          <div class="stat-label">技术文件</div>
        </div>
      </div>
      <div class="install-box">
        <code>{INSTALL_CMD}</code>
      </div>
      <p class="attribution">
        本仓库是
        <a href="https://github.com/ljagiello/ctf-skills">ljagiello/ctf-skills</a>
        的简体中文翻译版，原项目版权和许可证归原作者及贡献者所有。
      </p>
    </header>
    <div class="grid">
      {"".join(cards)}
    </div>
    <footer>
      <a href="{_get_repo_url()}">GitHub 仓库</a> &middot;
      <a href="https://agentskills.io">Agent Skills</a> &middot;
      MIT 许可证
    </footer>
  </div>
</body>
</html>"""


def main() -> None:
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    skills = []
    rendered = 0
    for skill_dir in discover_skills():
        text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        fm = parse_frontmatter(text)
        techniques = count_techniques(skill_dir)
        skills.append(
            {
                "dir_name": skill_dir.name,
                "description": fm.get("description", ""),
                "techniques": techniques,
            }
        )

        category_out = OUT_DIR / skill_dir.name
        for md in sorted(skill_dir.glob("*.md")):
            out_path = category_out / f"{md.stem}.html"
            crumb = [
                ("← 目录", "../index.html"),
                (skill_dir.name, "../index.html"),
                (md.name, ""),
            ]
            render_markdown_page(md, out_path, crumb)
            rendered += 1

    catalog_html = build_index_html(skills)
    (OUT_DIR / "index.html").write_text(catalog_html, encoding="utf-8")
    print(f"目录已生成: {OUT_DIR / 'index.html'}")
    total = sum(len(s["techniques"]) for s in skills)
    print(f"  {len(skills)} 个技能，{total} 个技术文件，{rendered} 个 .md 已渲染")


if __name__ == "__main__":
    main()
