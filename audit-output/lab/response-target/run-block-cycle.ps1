# File: run-block-cycle.ps1
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Drive one temporary nftables block and recovery cycle through the shipped endpoint command.

[CmdletBinding()]
param(
    [ValidateRange(30, 900)]
    [int]$DurationSeconds = 60,
    [string]$Intent = '',
    [string]$DigestSeed = 'terminus-response-target-lab-v1',
    [switch]$SkipDelete
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    if (-not $Intent) {
        $Intent = 'response-target-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join (
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($DigestSeed)) |
                ForEach-Object { $_.ToString('x2') }
        )
    }
    finally {
        $sha.Dispose()
    }

    function Invoke-Observer {
        param([Parameter(Mandatory = $true)][string]$Stage)

        $output = & docker compose exec -T observer python3 /opt/lab/observe.py `
            --stage $Stage --intent $Intent --digest $digest
        $code = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        if ($code -ne 0) {
            throw "Observer stage '$Stage' did not verify"
        }
    }

    function Send-EndpointCommand {
        param([Parameter(Mandatory = $true)][ValidateSet('add', 'delete')][string]$Command)

        $message = @{
            command    = $Command
            parameters = @{
                alert = @{
                    data = @{
                        srcip                     = '10.77.0.10'
                        terminus_intent_id        = $Intent
                        terminus_proposal_digest  = $digest
                        terminus_duration_seconds = $DurationSeconds
                    }
                }
            }
        } | ConvertTo-Json -Compress -Depth 8

        $output = $message | & docker compose exec -T target /usr/local/sbin/terminus-ip-block
        $code = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        if ($code -ne 0) {
            throw "Endpoint command '$Command' failed"
        }
        $parsed = ($output | Out-String).Trim() | ConvertFrom-Json
        if ($parsed.state -notin @('accepted', 'already_owned')) {
            throw "Endpoint command '$Command' returned state '$($parsed.state)'"
        }
        return $parsed
    }

    Write-Host "intent=$Intent"
    Write-Host "digest=$digest"
    Write-Host "duration=$DurationSeconds seconds"
    Write-Host ''

    Write-Host '== baseline =='
    Invoke-Observer -Stage baseline

    Write-Host '== add block =='
    $added = Send-EndpointCommand -Command add
    Write-Host "endpoint table: $($added.table)"

    Write-Host '== blocked =='
    Invoke-Observer -Stage blocked

    Write-Host "== waiting $($DurationSeconds + 5) seconds for kernel expiry =="
    Start-Sleep -Seconds ($DurationSeconds + 5)

    Write-Host '== recovered =='
    Invoke-Observer -Stage recovered

    if (-not $SkipDelete) {
        Write-Host '== delete owned table (undo) =='
        $deleted = Send-EndpointCommand -Command delete
        Write-Host "endpoint table: $($deleted.table)"
        Invoke-Observer -Stage table-absent
    }

    Write-Host ''
    Write-Host 'BLOCK/RECOVERY CYCLE VERIFIED'
}
finally {
    Pop-Location
}
