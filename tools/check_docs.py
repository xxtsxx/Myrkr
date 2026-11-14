#!/usr/bin/env python3
"""check_docs.py - structural integrity check for repository Markdown files.

Verifies every tracked/local *.md document under the repository root:
  1. Fenced code blocks (``` or ````) open and close cleanly.
  2. No empty ATX headings (`# `, `## `, ...).
  3. No duplicate heading titles at the same level within the same parent section
     (or across top-level siblings when there is no higher heading).
  4. Relative file links `[label](path)` resolve to existing files in the tree.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "bin", "obj", "__pycache__", ".venv", "venv", "node_modules"}

RE_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
RE_HEADING = re.compile(r"^(#{1,6})(?:\s+(.*?))?\s*$")
RE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def iter_md_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn.lower().endswith(".md"):
                yield os.path.join(dirpath, fn)


def strip_inline_code(line):
    return re.sub(r"`[^`]*`", "", line)


def check_file(path):
    rel = os.path.relpath(path, ROOT)
    errs = []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    fence_char = None
    fence_len = 0
    fence_line = 0

    # Track seen headings per parent chain: tuple(parent_titles) -> set((level, norm_title))
    stack = []  # [(level, title)]
    seen_under = {}

    for idx, line in enumerate(lines, 1):
        m_f = RE_FENCE.match(line)
        if m_f:
            tok = m_f.group(1)
            if fence_char is None:
                fence_char = tok[0]
                fence_len = len(tok)
                fence_line = idx
                continue
            if tok[0] == fence_char and len(tok) >= fence_len and line.strip() == tok:
                fence_char = None
                fence_len = 0
                continue

        if fence_char is not None:
            continue

        m_h = RE_HEADING.match(line)
        if m_h:
            lvl = len(m_h.group(1))
            title = (m_h.group(2) or "").strip()
            if not title:
                errs.append(f"{rel}:{idx}: empty heading")
                continue
            while stack and stack[-1][0] >= lvl:
                stack.pop()
            parent_key = tuple(s for _, s in stack)
            norm = re.sub(r"\s+", " ", title).lower()
            bucket = seen_under.setdefault(parent_key, set())
            if (lvl, norm) in bucket:
                errs.append(f"{rel}:{idx}: duplicate heading {title!r}")
            bucket.add((lvl, norm))
            stack.append((lvl, norm))

        clean = strip_inline_code(line)
        for m_l in RE_LINK.finditer(clean):
            raw_target = m_l.group(1).strip()
            if not raw_target or raw_target.startswith("#"):
                continue
            target = raw_target.split()[0].strip("<>")
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue
            file_part = target.split("#", 1)[0].split("?", 1)[0]
            if not file_part:
                continue
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), file_part))
            if not os.path.exists(resolved):
                errs.append(f"{rel}:{idx}: broken relative link -> {raw_target}")

    if fence_char is not None:
        errs.append(f"{rel}:{fence_line}: unclosed code fence ({fence_char * fence_len})")

    return errs


def main():
    files = list(iter_md_files(ROOT))
    all_errs = []
    for p in files:
        all_errs.extend(check_file(p))
    if all_errs:
        for e in all_errs:
            print("  ERROR", e)
        print(f"check_docs: {len(all_errs)} error(s) across {len(files)} markdown files")
        return 1
    print(f"check_docs: {len(files)} markdown files checked, 0 errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
