#Requires -Version 5.1
<#
  AI Cyber Shield - local harness launcher (Windows first).
  Builds and starts the Kali + OpenCode security harness in Docker Desktop, generating
  local secrets on first run. The harness listens only on 127.0.0.1.
#>
[CmdletBinding()]
param(
  [switch]$Rebuild,
  [switch]$Stop,
  [switch]$Logs
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# 1. Docker present and running?
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Fail "Docker was not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and start it."
}
try { docker info --format '{{.ServerVersion}}' | Out-Null }
catch { Fail "Docker Desktop is installed but not running. Start Docker Desktop, wait for it to be ready, then re-run." }

if ($Stop)  { docker compose down; Write-Host "Harness stopped." -ForegroundColor Green; exit 0 }
if ($Logs)  { docker compose logs -f --tail 100; exit 0 }

# 2. .env with generated secrets on first run.
function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ }) }

if (-not (Test-Path ".env")) {
  Write-Host "First run: creating .env with fresh local secrets..." -ForegroundColor Cyan
  $env_text = Get-Content ".env.example" -Raw
  $env_text = $env_text -replace "SHIELD_TOKEN=.*", "SHIELD_TOKEN=$(New-Secret)"
  $env_text = $env_text -replace "OPENCODE_SERVER_PASSWORD=.*", "OPENCODE_SERVER_PASSWORD=$(New-Secret)"
  Set-Content ".env" -Value $env_text -Encoding UTF8 -NoNewline
  Write-Host "  .env created. Add your AI provider key (e.g. OPENAI_API_KEY) and set SHIELD_MODEL in .env." -ForegroundColor Yellow
}

# 3. Read back the token so we can show the extension setup values.
$envMap = @{}
Get-Content ".env" | Where-Object { $_ -match "^\s*[A-Z_0-9]+\s*=" } | ForEach-Object {
  $k, $v = $_ -split "=", 2; $envMap[$k.Trim()] = $v.Trim()
}
$gwPort = if ($envMap["SHIELD_GATEWAY_PORT"]) { $envMap["SHIELD_GATEWAY_PORT"] } else { "7878" }
$ocPort = if ($envMap["SHIELD_OPENCODE_PORT"]) { $envMap["SHIELD_OPENCODE_PORT"] } else { "4096" }

$hasKey = $envMap.Keys | Where-Object { $_ -match "API_KEY$" -and $envMap[$_] }
if (-not $hasKey) {
  Write-Host "WARNING: no AI provider key set in .env. The agents need one (e.g. OPENAI_API_KEY=...)." -ForegroundColor Yellow
}

# 4. Build + start.
Write-Host "Building and starting the harness (first build downloads Kali + tools; this can take several minutes)..." -ForegroundColor Cyan
if ($Rebuild) { docker compose build --no-cache }
docker compose up -d --build

# 5. Wait for health.
Write-Host "Waiting for the harness to become healthy..." -ForegroundColor Cyan
$ok = $false
foreach ($i in 1..60) {
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$gwPort/api/health" -UseBasicParsing -TimeoutSec 3
    if ($r.StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep -Seconds 3 }
}

Write-Host ""
if ($ok) { Write-Host "AI Cyber Shield harness is running." -ForegroundColor Green }
else { Write-Host "Harness started but did not report healthy yet. Check logs: .\start.ps1 -Logs" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Extension settings  ->  Server URL: http://localhost:$gwPort"
Write-Host "                          Token:      $($envMap['SHIELD_TOKEN'])"
Write-Host "  OpenCode web UI     ->  http://localhost:$ocPort  (user: opencode, password in .env)"
Write-Host ""
Write-Host "  Stop:  .\start.ps1 -Stop     Logs:  .\start.ps1 -Logs" -ForegroundColor DarkGray
