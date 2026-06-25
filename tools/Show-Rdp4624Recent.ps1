<#
.SYNOPSIS
    Просмотр недавних 4624 с полями для диагностики RDP-login-monitor.
.EXAMPLE
    .\Show-Rdp4624Recent.ps1
    .\Show-Rdp4624Recent.ps1 -Minutes 30 -User jdoe
#>
[CmdletBinding()]
param(
    [int]$Minutes = 15,
    [string]$User = '',
    [int]$MaxEvents = 50
)

$start = (Get-Date).AddMinutes(-$Minutes)
Write-Host "Security 4624 since $($start.ToString('yyyy-MM-dd HH:mm:ss')) (local time)" -ForegroundColor Cyan

$events = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $start
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

if ($events.Count -eq 0) {
    Write-Host 'No 4624 events in window.'
    exit 0
}

function Get-EvProp($Event, [string]$Name) {
    $xml = [xml]$Event.ToXml()
    $n = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $n) { return '-' }
    return [string]$n.'#text'
}

$rows = foreach ($ev in $events) {
    $u = Get-EvProp $ev 'TargetUserName'
    if ($User -and $u -notlike "*$User*") { continue }
  [pscustomobject]@{
        TimeCreated = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        RecordId    = $ev.RecordId
        User        = $u
        LogonType   = Get-EvProp $ev 'LogonType'
        IpAddress   = Get-EvProp $ev 'IpAddress'
        Workstation = Get-EvProp $ev 'WorkstationName'
        Process     = Get-EvProp $ev 'LogonProcessName'
    }
}

$rows | Format-Table -AutoSize
Write-Host "`nTip: monitor log — Select-String -Path 'C:\ProgramData\RDP-login-monitor\Logs\*.log' -Pattern 'Notify:|Skip 4624|Notify dedup'"
