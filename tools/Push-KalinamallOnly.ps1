<#
.SYNOPSIS
    Push main to kalinamall only (skip public GitHub origin).
#>
[CmdletBinding()]
param(
    [string]$Branch = 'main'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot
try {
    git push kalinamall $Branch
    Write-Host "Pushed to kalinamall/$Branch (origin/GitHub skipped intentionally)."
} finally {
    Pop-Location
}
