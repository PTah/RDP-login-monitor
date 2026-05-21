---
description: Ultra-dense Python code generation rules to save output tokens
globs: "*.py"
---

# Python Token Optimization

- **Use Syntactic Sugar:** Prioritize list comprehensions, dict comprehensions, and ternary operators (`x if condition else y`) to keep code on a single line.
- **Built-in Libraries First:** Use standard libraries (`pathlib`, `json`, `subprocess`, `asyncio`) instead of introducing heavy external dependencies unless already in `requirements.txt`.
- **Type Hinting:** Do NOT add type hints (`def func(x: int) -> str:`) unless the existing file strictly uses them. Type hints consume significant tokens.
- **No Format Duplication:** When modifying scripts (like video downloaders), provide only the modified function or class method. Never output the `if __name__ == "__main__":` block or argument parsing logic if they haven't changed.
- **No Docstrings:** Strictly forbid writing `"""docstrings"""` or `# comments` explaining the logic.
- **Preserve yt-dlp Options:** Never rewrite, duplicate, or expand the `ydl_opts` configuration dictionary or custom extraction options. If changes are unrelated to download options, use a placeholder comment like `# ... existing ydl_opts ...` instead of outputting the full dictionary block.

