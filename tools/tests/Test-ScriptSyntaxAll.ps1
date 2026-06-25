. (Join-Path $PSScriptRoot '_TestLib.ps1')

$repo = Get-RdpMonitorRepoRoot
$files = @(
    'Deploy-LoginMonitor.ps1',
    'Login_Monitor.ps1',
    'Sac-Client.ps1',
    'RdpMonitor-TaskQuery.ps1',
    'update-rdp-monitor.ps1'
)

foreach ($rel in $files) {
    $path = Join-Path $repo $rel
    Invoke-RdpMonitorTestCase -Name "Syntax: $rel" -Script {
        Assert-True -Condition (Test-Path -LiteralPath $path) -Message "Missing $path"
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errs)
        if ($errs -and $errs.Count -gt 0) {
            throw ($errs | ForEach-Object { $_.ToString() } | Out-String)
        }
    }
}
