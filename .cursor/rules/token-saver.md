---
description: Global token-saving rules for ultra-concise communication and minimal context usage
globs: *
---

# Token-Saving Instructions

## Communication Strategy
- **Strictly no fluff:** Omit all greetings, pleasantries, apologies, and concluding remarks.
- **Direct answers only:** Start your response immediately with the solution, code block, or direct answer.
- **Extreme brevity:** Keep explanations under 2-3 sentences. Use bullet points instead of long paragraphs.

## Code Generation Guidelines
- **Do not restate existing code:** Never copy and paste parts of my existing file just to show where to insert changes.
- **Provide diffs only:** Show only the specific lines that need to be changed, added, or deleted. Use brief comments (`// ... existing code ...`) to show placement if necessary.
- **No boilerplate:** Do not generate setup code, imports, or boilerplate unless explicitly requested.
- **Single-line implementations:** Prefer concise, clean, short code syntax where readable (e.g., arrow functions, ternary operators).

## Code Review and Verification
- Do not explain why the code works unless asked.
- If the solution is simple, output *only* the code block and nothing else.
- If you need more information, ask a single, precise question. Do not list multiple hypotheticals.
