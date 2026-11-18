# File: setup.ps1
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Generate disposable SSH client and host keys for the response-target lab.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$state = Join-Path $root '.state'
$keys = Join-Path $state 'keys'
$hostkeys = Join-Path $state 'hostkeys'

New-Item -ItemType Directory -Force -Path $keys, $hostkeys | Out-Null

function New-LabKey {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Comment
    )

    if (Test-Path $Path) {
        if (-not (Test-Path "$Path.pub")) {
            throw "Existing private key has no public key: $Path"
        }
        Write-Host "Keeping existing key: $Path"
        return
    }

    # -N '""' is the Windows OpenSSH form for an empty passphrase.
    & ssh-keygen -q -t ed25519 -N '""' -C $Comment -f $Path
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen failed for $Path"
    }
    Write-Host "Generated key: $Path"
}

New-LabKey -Path (Join-Path $keys 'id_ed25519') -Comment 'terminus-response-target-client'
New-LabKey -Path (Join-Path $hostkeys 'target_ed25519') -Comment 'terminus-response-target-target-host'
New-LabKey -Path (Join-Path $hostkeys 'attacker_ed25519') -Comment 'terminus-response-target-attacker-host'

$targetHost = (Get-Content (Join-Path $hostkeys 'target_ed25519.pub') -Raw).Trim()
$attackerHost = (Get-Content (Join-Path $hostkeys 'attacker_ed25519.pub') -Raw).Trim()

$knownHosts = @(
    # Management names resolved by Docker DNS on single-node_default.
    # The existing network does not accept operator-supplied static addresses.
    "target $targetHost",
    "terminus-target-a $targetHost",
    "attacker $attackerHost",
    "terminus-attacker $attackerHost",
    # Attack-path addresses on the internal 10.77.0.0/24 link.
    "10.77.0.20 $targetHost",
    "10.77.0.10 $attackerHost"
)

$knownHostsPath = Join-Path $keys 'known_hosts'
Set-Content -Path $knownHostsPath -Value ($knownHosts -join "`n") -Encoding ascii -NoNewline
Add-Content -Path $knownHostsPath -Value "`n" -Encoding ascii

Write-Host ""
Write-Host "Lab keys are ready under $state"
Write-Host "The .state directory is ignored by git and must not be committed."
Write-Host ""
Write-Host "Next:"
Write-Host "  docker compose up -d --build"
