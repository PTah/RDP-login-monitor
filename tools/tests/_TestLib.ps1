Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RdpMonitorDeployFunctionsLoaded = $false

function Get-RdpMonitorRepoRoot {    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
}

function Assert-CommandExists {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    Assert-True -Condition ($null -ne $cmd) -Message "Command not found: $Name"
}

function Invoke-RdpMonitorTestCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    try {
        & $Script
        Write-Host "PASS: $Name"
    } catch {
        Write-Host "FAIL: $Name - $($_.Exception.Message)"
        throw
    }
}
