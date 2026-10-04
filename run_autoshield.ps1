param(
    [int]$Port = 8000,
    [switch]$SkipBuild,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dashboard = Join-Path $Root "dashboard"

Write-Host "AutoShield Edge AI - Stage-2 POC" -ForegroundColor Cyan
Write-Host "Model: Hybrid-v4 | Demo scenarios: Normal, DoS, Fuzzy, RPM spoof, Gear spoof, Mix / Combo"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is required but was not found in PATH."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is required but was not found in PATH."
}

if (-not $SkipBuild) {
    Push-Location $Dashboard
    try {
        if (-not (Test-Path (Join-Path $Dashboard "node_modules"))) {
            Write-Host "Installing dashboard dependencies..."
            cmd /c "npm ci"
            if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
        }
        Write-Host "Building dashboard..."
        cmd /c "npm run build"
        if ($LASTEXITCODE -ne 0) { throw "dashboard build failed" }
    }
    finally {
        Pop-Location
    }
}

$Server = Join-Path $Root "backend\server.py"
$Args = @($Server, "--host", "127.0.0.1", "--port", "$Port")
$Process = Start-Process python -ArgumentList $Args -WorkingDirectory $Root -PassThru -WindowStyle Hidden

try {
    $Url = "http://127.0.0.1:$Port"
    $Healthy = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 150
        try {
            $Health = Invoke-RestMethod "$Url/api/health" -TimeoutSec 1
            if ($Health.status -eq "ok") { $Healthy = $true; break }
        } catch {}
    }
    if (-not $Healthy) { throw "AutoShield backend did not become healthy." }

    Write-Host "POC ready: $Url" -ForegroundColor Green
    Write-Host "Backend PID: $($Process.Id)"
    if (-not $NoBrowser) { Start-Process $Url }
    Write-Host ""
    Write-Host "Demo order: Normal -> DoS -> Fuzzy -> RPM spoof -> Gear spoof -> Mix / Combo"
    Write-Host "Press ENTER when the demo is finished to stop the backend."
    Read-Host | Out-Null
}
finally {
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force
    }
}
