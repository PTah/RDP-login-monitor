---
description: High-density PowerShell script generation rules for minimal token usage
globs: "*.ps1, *.psm1"
---

# PowerShell Token Optimization

- **Use Short Aliases:** Use short aliases instead of full cmdlet names to drastically cut output tokens:
  - Use `gc` instead of `Get-Content`
  - Use `gci` instead of `Get-ChildItem`
  - Use `%` instead of `ForEach-Object`
  - Use `?` instead of `Where-Object`
  - Use `measure` instead of `Measure-Object`
- **Pipeline Over Loops:** Prefer pipeline chains (`gci | % { ... }`) over multi-line `foreach ($item in $items) { ... }` blocks.
- **No Help/Comments:** Do not generate `.SYNOPSIS`, `.DESCRIPTION`, or comment-based help at the top of scripts.
- **Omit Parameter Names:** Drop explicit parameter names where positional arguments are clear (e.g., use `gc file.txt` instead of `Get-Content -Path file.txt`).
- **Silent Execution:** Do not add verbose logging, `Write-Host`, or `Write-Output` unless explicitly asked to create UI/logs.
- **Preserve CLI Arguments:** Do not duplicate full multi-line `yt-dlp` command-line arguments, format strings, or output templates if they are not the subject of the modifications. Use placeholders or variable references.
