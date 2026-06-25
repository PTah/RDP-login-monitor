# Push main to origin / example-admin with production secrets and paths.
# GitHub (origin) stays sanitized — never push this commit to origin.
# Usage: .\scripts\Push-PrivateMirror.ps1 origin|example-admin
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('origin', 'example-admin')]
    [string]$Target
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$remote = $Target
git remote get-url $remote 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "remote not configured: $remote (git remote add $remote <url>)"
}

if ((git status --porcelain)) {
    throw 'working tree not clean; commit or stash first'
}

$before = (git rev-parse HEAD).Trim()
git fetch $remote main 2>$null
if ($LASTEXITCODE -ne 0) {
    git fetch $remote 2>$null
}

# Production-only files: real tokens, NETLOGON paths, org hostnames.
$privateFiles = @(
    'login_monitor.settings.example.ps1',
    'update-rdp-monitor.ps1',
    'exchange_monitor.settings.example.ps1'
)

$hadPrivate = $false
foreach ($f in $privateFiles) {
    $ref = "${remote}/main"
    git rev-parse "$ref`:$f" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        git checkout "$ref" -- $f
        $hadPrivate = $true
        Write-Output "restored from ${remote}/main: $f"
    } else {
        Write-Warning "skip (not on ${remote}/main): $f"
    }
}

if (-not $hadPrivate) {
    throw "no private files on ${remote}/main; restore production files manually once, then re-run"
}

& "$PSScriptRoot\Rewrite-GitHostUrls.ps1" -Target $Target

git add -A
$status = git status --porcelain
if (-not $status) {
    Write-Output "no changes vs local main; pushing as-is to $remote"
    git push $remote main
    exit 0
}

git commit -m "chore(private): sync production secrets and paths for ${Target} mirror"
git push $remote main
git reset --hard $before
Write-Output "pushed $remote with production files; local main reset to $before (GitHub-safe)"
