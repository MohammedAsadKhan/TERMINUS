# Install only the dedicated verification PUBLIC key. Guest passwords stay local.
$ErrorActionPreference = 'Stop'
$verificationKey = Join-Path $env:USERPROFILE '.ssh\terminus_lab_ed25519'
if (-not (Test-Path -LiteralPath ($verificationKey + '.pub'))) { throw 'Verification public key is missing.' }
$publicKey = 'from="192.168.56.1",restrict ' + (Get-Content -LiteralPath ($verificationKey + '.pub') -Raw).Trim()
foreach ($guest in @('kali@192.168.56.102', 'labadmin@192.168.56.103')) {
    Write-Host "Installing verification public key on $guest. Enter that VM login password if requested."
    $publicKey | ssh -o StrictHostKeyChecking=yes $guest 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys'
    if ($LASTEXITCODE -ne 0) { throw "Key installation failed for $guest" }
    ssh -i $verificationKey -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes $guest hostname
    if ($LASTEXITCODE -ne 0) { throw "Key verification failed for $guest" }
}
Write-Host 'Both verification keys installed. Ubuntu read-only sudo access is a separate setup step.'
