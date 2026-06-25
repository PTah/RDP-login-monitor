$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\Deploy-LoginMonitor.ps1'),
    [ref]$null,
    [ref]$errs
)
if ($errs) { $errs | ForEach-Object { $_.ToString() }; exit 1 }
Write-Output 'OK'
