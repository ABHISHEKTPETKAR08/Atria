<#
.SYNOPSIS
    Deploy the Smart Observability Tier-2 SaaS (host.py) to Azure App Service (Linux, Python 3.11).

.DESCRIPTION
    az login -> az group create -> az appservice plan create -> az webapp up -> startup/hardening -> health check.
    Only the Tier-2 files are staged and uploaded (the edge collector and local DB/buffers never leave this PC).
    Typical run time on a B1 plan: ~2-3 minutes.

.EXAMPLE
    .\deploy_azure.ps1 -AppName smartobs-cicada-team7
    .\deploy_azure.ps1 -AppName smartobs-cicada-team7 -Location eastus -IngestToken "demo-secret-123"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$')]
    [string]$AppName,                                   # globally unique -> https://<AppName>.azurewebsites.net
    [string]$ResourceGroup = "rg-smart-observability",
    [string]$Location      = "centralindia",
    [string]$PlanName      = "asp-smart-observability",
    [string]$Sku           = "B1",                      # B1 supports Always On; F1 is free but sleeps
    [string]$Runtime       = "PYTHON:3.11",
    [string]$IngestToken   = "demo-secret-123"          # must match the collectors' --token
)

$ErrorActionPreference = "Stop"
$timer = [Diagnostics.Stopwatch]::StartNew()

function Invoke-Az {
    # Runs an az command, masks the ingest token in the echo, and fails fast on non-zero exit codes.
    $shown = ($args -join ' ') -replace [regex]::Escape($IngestToken), '***'
    Write-Host "  > az $shown" -ForegroundColor DarkGray
    & az @args
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI command failed (exit $LASTEXITCODE): az $shown" }
}

function Step($n, $text) { Write-Host "`n[$n/7] $text" -ForegroundColor Cyan }

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI not found. Install it: winget install -e --id Microsoft.AzureCLI  (then reopen PowerShell)"
}

# 1. Login (skipped if a session already exists)
Step 1 "Azure login"
$ErrorActionPreference = "Continue"            # PS 5.1 would throw on redirected native stderr
az account show --output none 2>$null
$loggedIn = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = "Stop"
if (-not $loggedIn) { Invoke-Az login --output none }
$sub = az account show --query "name" -o tsv
Write-Host "  subscription: $sub"

# 2. Resource group
Step 2 "Resource group '$ResourceGroup' ($Location)"
Invoke-Az group create --name $ResourceGroup --location $Location --output none

# 3. Linux App Service plan
Step 3 "App Service plan '$PlanName' ($Sku, Linux)"
Invoke-Az appservice plan create --name $PlanName --resource-group $ResourceGroup --location $Location `
    --sku $Sku --is-linux --output none

# 4. Stage Tier-2 files only and deploy with az webapp up (Oryx installs requirements.txt during build)
Step 4 "Deploying code with az webapp up ($Runtime)"
$stage = Join-Path $PSScriptRoot ".deploy"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
foreach ($f in @("host.py", "requirements.txt", "gunicorn.conf.py", "Procfile")) {
    Copy-Item (Join-Path $PSScriptRoot $f) $stage
}
Push-Location $stage
try {
    Invoke-Az webapp up --name $AppName --resource-group $ResourceGroup --plan $PlanName `
        --location $Location --runtime $Runtime --os-type Linux --output none
} finally {
    Pop-Location
}

# 5. Startup command (gunicorn.conf.py binds 0.0.0.0:$PORT, default 8000) + platform hardening
Step 5 "Startup command and hardening"
Invoke-Az webapp config set --name $AppName --resource-group $ResourceGroup `
    --startup-file "gunicorn --config gunicorn.conf.py host:app" `
    --always-on true --http20-enabled true --min-tls-version 1.2 --ftps-state Disabled --output none
Invoke-Az webapp update --name $AppName --resource-group $ResourceGroup --https-only true --output none

# 6. App settings. DB on local /tmp: SQLite WAL needs a local filesystem (not the /home SMB share).
#    Note: /tmp is ephemeral - data resets on restart (fine for a demo; use Azure SQL/Postgres for persistence).
Step 6 "App settings"
Invoke-Az webapp config appsettings set --name $AppName --resource-group $ResourceGroup --output none --settings `
    "INGEST_TOKEN=$IngestToken" "DB_PATH=/tmp/received.db" "WEBSITES_PORT=8000" "SCM_DO_BUILD_DURING_DEPLOYMENT=true"

# 7. Wait for /health
Step 7 "Health check"
$base = "https://$AppName.azurewebsites.net"
$healthy = $false
for ($i = 1; $i -le 18 -and -not $healthy; $i++) {
    try {
        $h = Invoke-RestMethod -Uri "$base/health" -TimeoutSec 15
        if ($h.status -eq "ok") { $healthy = $true; Write-Host "  healthy: journal_mode=$($h.journal_mode) events=$($h.events)" -ForegroundColor Green }
    } catch {
        Write-Host "  waiting for container to start ($i/18)..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
    }
}

$timer.Stop()
Write-Host ""
if ($healthy) {
    Write-Host "Deployed in $([int]$timer.Elapsed.TotalSeconds)s" -ForegroundColor Green
} else {
    Write-Host "Deployed, but /health did not answer yet. Logs: az webapp log tail -n $AppName -g $ResourceGroup" -ForegroundColor Yellow
}
Write-Host "  Dashboard : $base/"
Write-Host "  Ingest    : $base/ingest"
Write-Host "  Collector : python collector.py --target azure --app-name $AppName"
Write-Host "  Tear down : az group delete -n $ResourceGroup --yes --no-wait"
