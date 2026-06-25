. (Join-Path $PSScriptRoot '_TestLib.ps1')
. (Join-Path $PSScriptRoot '_DeployFunctionsLoader.ps1')
$repo = Get-RdpMonitorRepoRoot

Invoke-RdpMonitorTestCase -Name 'Deploy functions load (RDP_DEPLOY_FUNCTIONS_ONLY)' -Script {
    Assert-CommandExists -Name 'Initialize-RdpMonitorDeployTaskQuery'
    Assert-CommandExists -Name 'Test-RdpMonitorDeployMainTaskNeedsUnlimitedExecutionTime'
    Assert-CommandExists -Name 'Write-RdpMonitorDeployScheduledTaskVerification'
    Assert-CommandExists -Name 'Get-RdpMonitorDeployTaskExecutionTimeLimitLabelFromResolved'
    Assert-CommandExists -Name 'Convert-RdpMonitorDeployTaskExecutionTimeLimitValue'
}

Invoke-RdpMonitorTestCase -Name 'Deploy ExecutionTimeLimit accepts PT0S string (Get-ScheduledTask shape)' -Script {
    Assert-True -Condition (Test-RdpMonitorDeployTaskExecutionLimitUnlimitedValue -Limit 'PT0S') `
        -Message 'PT0S string must be treated as unlimited'
    $resolved = [pscustomobject]@{ Limit = 'PT0S'; Source = 'Get-ScheduledTask' }
    $label = Get-RdpMonitorDeployTaskExecutionTimeLimitLabelFromResolved -Resolved $resolved
    Assert-True -Condition ($label -eq 'PT0S') -Message "Expected PT0S label, got $label"
    Assert-True -Condition (Test-RdpMonitorDeployTaskExecutionLimitUnlimitedValue -Limit $resolved.Limit) `
        -Message 'Resolved PT0S string must pass unlimited check'
}

Invoke-RdpMonitorTestCase -Name 'Deploy pre-check task limit (no throw on early path)' -Script {
    $needsFix = Test-RdpMonitorDeployMainTaskNeedsUnlimitedExecutionTime -ShareRoot $repo -TaskName 'RDP-Login-Monitor-UnitTest-Missing'
    Assert-True -Condition ($needsFix -is [bool]) -Message 'Test-RdpMonitorDeployMainTaskNeedsUnlimitedExecutionTime must return bool'
}

Invoke-RdpMonitorTestCase -Name 'Deploy verification after Initialize (no missing command)' -Script {
    [void](Initialize-RdpMonitorDeployTaskQuery -ShareRoot $repo)
    Assert-CommandExists -Name 'Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved'
    $ok = Write-RdpMonitorDeployScheduledTaskVerification -ShareRoot $repo -TaskName 'RDP-Login-Monitor-UnitTest-Missing'
    Assert-True -Condition ($ok -is [bool]) -Message 'Write-RdpMonitorDeployScheduledTaskVerification must return bool'
}
