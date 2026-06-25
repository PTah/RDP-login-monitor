<#
.SYNOPSIS
    Smoke/autotests for RDP-login-monitor deploy and SAC paths.
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\Run-RdpMonitorTests.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testsDir = Join-Path $PSScriptRoot 'tests'
$suites = @(
    'Test-ScriptSyntaxAll.ps1',
    'Test-TaskQueryModule.ps1',
    'Test-DeployTaskLimit.ps1',
    'Test-SecurityPollCursor.ps1',
    'Test-SendDeploySacNotice.ps1'
)

Write-Host '=== RDP-login-monitor autotests ==='
$failed = 0
foreach ($suite in $suites) {
    $path = Join-Path $testsDir $suite
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "FAIL: missing suite $path"
        $failed++
        continue
    }
    Write-Host "--- $suite ---"
    try {
        & $path
    } catch {
        Write-Host "SUITE FAILED: $suite - $($_.Exception.Message)"
        $failed++
    }
}

if ($failed -gt 0) {
    Write-Host ('=== FAILED ({0} suite(s)) ===' -f $failed)
    exit 1
}

Write-Host '=== ALL PASSED ==='
exit 0
