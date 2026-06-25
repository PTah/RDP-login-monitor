param([string]$Path = (Join-Path $PSScriptRoot '..\Login_Monitor.ps1'))
$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Path), [ref]$null, [ref]$errs)
if ($errs) {
    $errs | ForEach-Object { $_.ToString() }
    exit 1
}
Write-Output 'OK'
