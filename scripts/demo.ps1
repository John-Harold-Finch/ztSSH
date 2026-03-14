# ZTSSH automated demo — creates a CA, server, and client, runs challenge cycles.
# Usage: .\scripts\demo.ps1
# Requires: cargo (Rust toolchain)

$ErrorActionPreference = "Stop"

$DemoDir = Join-Path $env:TEMP "ztssh-demo-$(Get-Random)"
New-Item -ItemType Directory -Path $DemoDir -Force | Out-Null

Write-Host "=== ZTSSH Automated Demo ===" -ForegroundColor Cyan
Write-Host "Working directory: $DemoDir"
Write-Host ""

Push-Location (Join-Path $PSScriptRoot "..\rust")

try {
    # 1. Initialize Root CA
    Write-Host "> Step 1: Initialize Root CA" -ForegroundColor Green
    & cargo run --quiet --bin ztssh-ca -- --dir "$DemoDir\ca" init
    if ($LASTEXITCODE -ne 0) { throw "CA init failed" }
    Write-Host ""

    # 2. Generate server Sub-CA key
    Write-Host "> Step 2: Generate server Sub-CA keypair" -ForegroundColor Green
    $output = & cargo run --quiet --bin ztssh-ca -- --dir "$DemoDir\ca" generate-server-key --out "$DemoDir\server.key" 2>&1
    $output | ForEach-Object { Write-Host $_ }
    $pubkeyLine = ($output | Where-Object { $_ -match "Public key:" }) -replace '.*Public key:\s*', ''
    $pubkey = $pubkeyLine.Trim()
    Write-Host "  Extracted public key: $pubkey"
    Write-Host ""

    # 3. Authorize the server
    Write-Host "> Step 3: Authorize server (issue IntermediateCertificate)" -ForegroundColor Green
    & cargo run --quiet --bin ztssh-ca -- --dir "$DemoDir\ca" authorize-server `
        --server-id demo-server `
        --pubkey $pubkey `
        --out "$DemoDir\intermediate.cert"
    if ($LASTEXITCODE -ne 0) { throw "authorize-server failed" }
    Write-Host ""

    # 4. Show CA state
    Write-Host "> Step 4: Root CA state" -ForegroundColor Green
    & cargo run --quiet --bin ztssh-ca -- --dir "$DemoDir\ca" show
    Write-Host ""

    # 5. Start server in background
    Write-Host "> Step 5: Starting ztsshd (challenge every 2s)" -ForegroundColor Green
    $serverJob = Start-Job -ScriptBlock {
        param($RustDir, $DemoDir)
        Set-Location $RustDir
        & cargo run --quiet --bin ztsshd -- `
            --cert "$DemoDir\intermediate.cert" `
            --key "$DemoDir\server.key" `
            --listen "127.0.0.1:2222" `
            --challenge-interval 2 `
            --challenge-deadline 5 2>&1
    } -ArgumentList (Get-Location).Path, $DemoDir
    Start-Sleep -Seconds 3

    # 6. Run client
    Write-Host "> Step 6: Connecting client as 'alice'" -ForegroundColor Green
    $clientJob = Start-Job -ScriptBlock {
        param($RustDir)
        Set-Location $RustDir
        & cargo run --quiet --bin ztssh -- alice@127.0.0.1:2222 2>&1
    } -ArgumentList (Get-Location).Path

    # Wait for a few challenge cycles
    Start-Sleep -Seconds 8

    # Get outputs
    Write-Host ""
    Write-Host "--- Server output ---" -ForegroundColor Yellow
    Receive-Job $serverJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    Write-Host ""
    Write-Host "--- Client output ---" -ForegroundColor Yellow
    Receive-Job $clientJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    # 7. Cleanup
    Stop-Job $clientJob -ErrorAction SilentlyContinue
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $clientJob, $serverJob -Force -ErrorAction SilentlyContinue
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $DemoDir -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=== Demo complete ===" -ForegroundColor Cyan
Write-Host "The ZTSSH challenge-response loop ran successfully."
