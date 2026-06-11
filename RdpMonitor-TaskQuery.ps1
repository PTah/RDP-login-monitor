<#
.SYNOPSIS
    Запрос задач планировщика RDP-login-monitor через schtasks /Query /XML (fallback для Get-ScheduledTask).
#>

function Get-RdpMonitorSchtasksExe {
    return Join-Path $env:SystemRoot 'System32\schtasks.exe'
}

function Get-RdpMonitorScheduledTaskXmlDocument {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )

    $exe = Get-RdpMonitorSchtasksExe
    $prevEa = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $raw = & $exe /Query /TN $TaskName /XML 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        $text = ($raw | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        if ($text -notmatch '(?s)<Task\b') { return $null }
        return [xml]$text
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $prevEa
    }
}

function Test-RdpMonitorScheduledTaskExistsViaSchtasks {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )
    return ($null -ne (Get-RdpMonitorScheduledTaskXmlDocument -TaskName $TaskName))
}

function Convert-RdpMonitorScheduledTaskExecutionTimeLimitText {
    param([string]$LimitText)

    if ([string]::IsNullOrWhiteSpace($LimitText)) { return $null }
    $t = $LimitText.Trim()
    if ($t -eq 'PT0S') { return [TimeSpan]::Zero }
    try {
        return [System.Xml.XmlConvert]::ToTimeSpan($t)
    } catch {
        return $null
    }
}

function Get-RdpMonitorScheduledTaskExecutionTimeLimitFromDocument {
    param([xml]$Doc)

    if ($null -eq $Doc) { return $null }

    $ns = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $node = $Doc.SelectSingleNode('//t:Settings/t:ExecutionTimeLimit', $ns)
    if ($null -eq $node) {
        $node = $Doc.SelectSingleNode('//*[local-name()="Settings"]/*[local-name()="ExecutionTimeLimit"]')
    }
    if ($null -eq $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) { return $null }
    return Convert-RdpMonitorScheduledTaskExecutionTimeLimitText -LimitText $node.InnerText.Trim()
}

function Get-RdpMonitorScheduledTaskActionFromDocument {
    param([xml]$Doc)

    if ($null -eq $Doc) { return $null }

    $ns = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $cmdNode = $Doc.SelectSingleNode('//t:Actions/t:Exec/t:Command', $ns)
    $argNode = $Doc.SelectSingleNode('//t:Actions/t:Exec/t:Arguments', $ns)
    if ($null -eq $cmdNode) {
        $cmdNode = $Doc.SelectSingleNode('//*[local-name()="Actions"]/*[local-name()="Exec"]/*[local-name()="Command"]')
    }
    if ($null -eq $argNode) {
        $argNode = $Doc.SelectSingleNode('//*[local-name()="Actions"]/*[local-name()="Exec"]/*[local-name()="Arguments"]')
    }
    if ($null -eq $cmdNode) { return $null }

    return [pscustomobject]@{
        Execute   = [string]$cmdNode.InnerText
        Arguments = if ($null -ne $argNode) { [string]$argNode.InnerText } else { '' }
    }
}

function Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue {
    param($Limit)

    if ($null -eq $Limit) { return $false }
    if ($Limit -isnot [TimeSpan]) { return $false }
    if ($Limit.Ticks -le 0) { return $true }
    if ($Limit.TotalDays -ge 999) { return $true }
    return $false
}

function Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )

    try {
        $limit = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Select-Object -First 1).Settings.ExecutionTimeLimit
        return [pscustomobject]@{
            Limit  = $limit
            Source = 'Get-ScheduledTask'
        }
    } catch { }

    $doc = Get-RdpMonitorScheduledTaskXmlDocument -TaskName $TaskName
    if ($null -eq $doc) {
        return [pscustomobject]@{
            Limit  = $null
            Source = 'missing'
        }
    }

    $limit = Get-RdpMonitorScheduledTaskExecutionTimeLimitFromDocument -Doc $doc
    return [pscustomobject]@{
        Limit  = $limit
        Source = 'schtasks-xml'
    }
}

function Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimited {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )

    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    if ($resolved.Source -eq 'missing') { return $false }
    return (Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue -Limit $resolved.Limit)
}

function Test-RdpMonitorScheduledTaskNeedsUnlimitedExecutionTimeLimit {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )

    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    if ($resolved.Source -eq 'missing') { return $true }
    return (-not (Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue -Limit $resolved.Limit))
}

function Get-RdpMonitorScheduledTaskExecutionTimeLimitLabel {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName
    )

    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    if ($resolved.Source -eq 'missing') { return '(task missing)' }

    $limit = $resolved.Limit
    if ($null -eq $limit) { return '(null)' }
    if ($limit -is [TimeSpan] -and $limit.Ticks -le 0) { return 'PT0S' }
    return $limit.ToString()
}

function Test-RdpMonitorScheduledTaskActionMatchesViaSchtasks {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName,
        [Parameter(Mandatory = $true)][string]$ExpectedExe,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments
    )

    $doc = Get-RdpMonitorScheduledTaskXmlDocument -TaskName $TaskName
    if ($null -eq $doc) { return $false }

    $action = Get-RdpMonitorScheduledTaskActionFromDocument -Doc $doc
    if ($null -eq $action) { return $false }
    if ($action.Execute.Trim() -ne $ExpectedExe.Trim()) { return $false }
    return ($action.Arguments.Trim() -eq $ExpectedArguments.Trim())
}
