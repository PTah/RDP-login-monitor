---
description: Code generation syntax restrictions to minimize output tokens
globs: "*.{ts,js,py,cs}"
---

# Syntax Optimization

- **No JSDoc/Docstrings:** Do NOT write documentation, comments, JSDoc, or docstrings for generated functions unless explicitly asked.
- **No logs or prints:** Remove all `console.log`, `print()`, or debugging statements from the final code output.
- **Use concise syntax:** 
  - In JavaScript/TypeScript: Use arrow functions, optional chaining (`?.`), nullish coalescing (`??`), and destructuring.
  - In Python: Use list comprehensions, dict comprehensions, and built-in functions.
- **Minimize imports:** Do not output the `import` statements section if the required packages are standard and already exist in the file.
