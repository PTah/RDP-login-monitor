. (Join-Path $PSScriptRoot '_TestLib.ps1')

function Test-RdpMonitorDeploySacHostLabelStrictMode {
    Set-StrictMode -Version Latest
    $hostLabel = [string]$env:COMPUTERNAME
    if (Get-Variable -Name ServerDisplayName -Scope Script -ErrorAction SilentlyContinue) {
        $sdn = (Get-Variable -Name ServerDisplayName -Scope Script -ValueOnly)
        if ($null -ne $sdn -and -not [string]::IsNullOrWhiteSpace([string]$sdn)) {
            $hostLabel = [string]$sdn.Trim()
        }
    }
    return $hostLabel
}

Invoke-RdpMonitorTestCase -Name 'Deploy SAC host label without ServerDisplayName (StrictMode)' -Script {
    $label = Test-RdpMonitorDeploySacHostLabelStrictMode
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($label)) -Message 'Host label must not be empty'
    Assert-True -Condition ($label -eq [string]$env:COMPUTERNAME) -Message 'Expected COMPUTERNAME when ServerDisplayName unset'
}

Invoke-RdpMonitorTestCase -Name 'Deploy SAC host label with ServerDisplayName (StrictMode)' -Script {
    $script:ServerDisplayName = 'Test-Server-Display'
    try {
        $label = Test-RdpMonitorDeploySacHostLabelStrictMode
        Assert-True -Condition ($label -eq 'Test-Server-Display') -Message 'Expected ServerDisplayName value'
    } finally {
        Remove-Variable -Name ServerDisplayName -Scope Script -ErrorAction SilentlyContinue
    }
}

Invoke-RdpMonitorTestCase -Name 'Login_Monitor -SendDeploySacNotice does not fail on StrictMode host label' -Script {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'SKIP: requires elevated PowerShell (administrator)'
        return
    }

    $repo = Get-RdpMonitorRepoRoot
    $tempRoot = Join-Path $env:TEMP ("rdp-monitor-test-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tempRoot 'Logs') -Force | Out-Null

    $settings = @'
$UseSAC = 'off'
'@
    $settingsPath = Join-Path $tempRoot 'login_monitor.settings.ps1'
    [System.IO.File]::WriteAllText($settingsPath, $settings, (New-Object System.Text.UTF8Encoding $true))

    Copy-Item -LiteralPath (Join-Path $repo 'Login_Monitor.ps1') -Destination (Join-Path $tempRoot 'Login_Monitor.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $repo 'Sac-Client.ps1') -Destination (Join-Path $tempRoot 'Sac-Client.ps1') -Force

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -SendDeploySacNotice' -f (Join-Path $tempRoot 'Login_Monitor.ps1')
    $psi.WorkingDirectory = $tempRoot
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    try {
        if ($stderr -match 'ServerDisplayName|VariableIsUndefined') {
            throw "SendDeploySacNotice stderr contains StrictMode error: $stderr"
        }
        Assert-True -Condition ($proc.ExitCode -eq 0) -Message "Expected exit 0 with UseSAC=off, got $($proc.ExitCode); stderr=$stderr stdout=$stdout"
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
