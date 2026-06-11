. (Join-Path $PSScriptRoot '_TestLib.ps1')

$repo = Get-RdpMonitorRepoRoot
$taskQuery = Join-Path $repo 'RdpMonitor-TaskQuery.ps1'

Invoke-RdpMonitorTestCase -Name 'TaskQuery file exists' -Script {
    Assert-True -Condition (Test-Path -LiteralPath $taskQuery) -Message "Missing $taskQuery"
}

Invoke-RdpMonitorTestCase -Name 'TaskQuery dot-source defines core commands' -Script {
    . $taskQuery
    Assert-CommandExists -Name 'Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved'
    Assert-CommandExists -Name 'Test-RdpMonitorScheduledTaskNeedsUnlimitedExecutionTimeLimit'
    Assert-CommandExists -Name 'Get-RdpMonitorScheduledTaskExecutionTimeLimitLabel'
}
