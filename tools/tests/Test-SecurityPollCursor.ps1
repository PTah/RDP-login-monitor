. (Join-Path $PSScriptRoot '_TestLib.ps1')

function Test-RdpSecurityPollCursorResolve {
    param(
        [datetime]$Now,
        [int]$MaxAgeMinutes,
        [Nullable[datetime]]$SavedCursor
    )

    $maxAgeMin = [math]::Max(1, $MaxAgeMinutes)
    $lookbackFloor = $Now.AddMinutes(-1 * $maxAgeMin)
    if ($null -eq $SavedCursor) {
        return $lookbackFloor
    }
    if ($SavedCursor -lt $lookbackFloor) {
        return $lookbackFloor
    }
    return $SavedCursor
}

Invoke-RdpMonitorTestCase -Name 'Security cursor: missing file uses lookback floor' -Script {
    $now = Get-Date '2026-06-15T12:00:00'
    $resolved = Test-RdpSecurityPollCursorResolve -Now $now -MaxAgeMinutes 60 -SavedCursor $null
    $expected = $now.AddMinutes(-60)
    Assert-True -Condition ($resolved -eq $expected) -Message 'Expected lookback floor when cursor missing'
}

Invoke-RdpMonitorTestCase -Name 'Security cursor: stale saved cursor capped to lookback floor' -Script {
    $now = Get-Date '2026-06-15T12:00:00'
    $stale = $now.AddMinutes(-120)
    $resolved = Test-RdpSecurityPollCursorResolve -Now $now -MaxAgeMinutes 60 -SavedCursor $stale
    $expected = $now.AddMinutes(-60)
    Assert-True -Condition ($resolved -eq $expected) -Message 'Expected cap at lookback floor for stale cursor'
}

Invoke-RdpMonitorTestCase -Name 'Security cursor: recent saved cursor preserved' -Script {
    $now = Get-Date '2026-06-15T12:00:00'
    $recent = $now.AddMinutes(-5)
    $resolved = Test-RdpSecurityPollCursorResolve -Now $now -MaxAgeMinutes 60 -SavedCursor $recent
    Assert-True -Condition ($resolved -eq $recent) -Message 'Expected recent cursor unchanged'
}

Invoke-RdpMonitorTestCase -Name 'Login_Monitor defines Security poll cursor helpers' -Script {
    $repo = Get-RdpMonitorRepoRoot
    $text = Get-Content -LiteralPath (Join-Path $repo 'Login_Monitor.ps1') -Raw
    Assert-True -Condition ($text -match 'Get-RdpSecurityPollCursor') -Message 'Missing Get-RdpSecurityPollCursor'
    Assert-True -Condition ($text -match 'Set-RdpSecurityPollCursor') -Message 'Missing Set-RdpSecurityPollCursor'
    Assert-True -Condition ($text -match '\$SecurityPollCursorFile') -Message 'Missing SecurityPollCursorFile'
}
