---
description: Global token-saving, cost control, and context management rules
globs: *
---

# Global Optimization & Cost Control

## ?? Answers
-Always answer briefly and only to the point, otherwise only if it is stated in the question or when it is not possible to answer briefly.

## ?? Context & Local Data
- **Strict file targeting:** Work ONLY with files explicitly provided via `@` or open in the active editor tab. Do not use global codebase search unless requested.
- **Local assets only:** Always work with local copies of repositories and dependencies. Never request external web resources or re-download packages without a explicit build error.
- **Size Limit:** Do not load files larger than 500 lines into the context unless strictly necessary.

## ?? Git & Commits Management
- **Automatic commits are strictly FORBIDDEN.** Never execute `git commit` or `git push` without an explicit user command.
- Only suggest a commit after phrases like: "Сделай коммит", "Зафиксируй изменения", "Push".
- Before committing: display `git diff --stat` and wait for explicit user confirmation.
- Use Conventional Commits format (`feat:`, `fix:`, `refactor:`, `docs:`).

## ?? Output Format & Brevity
- **Strictly no fluff:** Omit greetings, apologies, and closing pleasantries.
- **Diff-style only:** Output only modified code fragments, never duplicate unchanged logic or whole files.
- **Extreme brevity:** Explanations must be 1-3 sentences max. Use documentation links instead of long texts.
- If a task doesn't require code, respond strictly with text. If in doubt, ask ONE precise clarifying question.

## ?? Model Routing Reminder
- Simple questions, explanations, docs ? Use lightweight models (e.g., `gpt-4o-mini`, `claude-3-haiku`).
- Complex code generation, refactoring, and debugging ? Use advanced models (e.g., `claude-3.5-sonnet`).
- Do not switch models without an explicit reason.

