# Dot-source from a test .ps1 at script scope after _TestLib.ps1 (not from a function/scriptblock).
if ($script:RdpMonitorDeployFunctionsLoaded) { return }

$repo = Get-RdpMonitorRepoRoot
$prev = $env:RDP_DEPLOY_FUNCTIONS_ONLY
$env:RDP_DEPLOY_FUNCTIONS_ONLY = '1'
try {
    . (Join-Path $repo 'Deploy-LoginMonitor.ps1')
} finally {
    if ($null -eq $prev) {
        Remove-Item Env:RDP_DEPLOY_FUNCTIONS_ONLY -ErrorAction SilentlyContinue
    } else {
        $env:RDP_DEPLOY_FUNCTIONS_ONLY = $prev
    }
}
$script:RdpMonitorDeployFunctionsLoaded = $true
