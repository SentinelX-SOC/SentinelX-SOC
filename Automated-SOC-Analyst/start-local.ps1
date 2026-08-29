[CmdletBinding()]
param(
    [switch]$SkipHealthWait
)

$ErrorActionPreference = "Stop"

$backendRoot = $PSScriptRoot
$workspaceRoot = Split-Path -Parent $backendRoot
$mlRoot = Join-Path $workspaceRoot "autonomous-threat-defense"
$python = Join-Path $workspaceRoot ".venv-1\Scripts\python.exe"
$mlPort = 9000
$backendPort = 8000

function Test-PortFree([int]$Port) {
    return @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue).Count -eq 0
}

function Wait-Health([string]$Url, [scriptblock]$Ready, [int]$TimeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 2
            if (& $Ready $response) {
                return $response
            }
        } catch {
            # The process may still be starting.
        }
        Wait-Event -Timeout 0.25 | Out-Null
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for readiness at $Url"
}

foreach ($path in @($python, $backendRoot, $mlRoot, (Join-Path $backendRoot ".env"), (Join-Path $mlRoot "data\processed\isolation_forest.joblib"), (Join-Path $mlRoot "data\processed\features_ml_demo.parquet"))) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required startup path is missing: $path"
    }
}

foreach ($port in @($mlPort, $backendPort)) {
    if (-not (Test-PortFree $port)) {
        throw "Port $port is already in use; refusing to launch duplicate services."
    }
}

$mlProcess = Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "ml_service:app", "--host", "127.0.0.1", "--port", "$mlPort") -WorkingDirectory $mlRoot -PassThru
try {
    if (-not $SkipHealthWait) {
        $mlHealth = Wait-Health "http://127.0.0.1:$mlPort/health" { param($body) $body.inference_ready -eq $true -and $body.model_loaded -eq $true }
        Write-Host ("ML adapter ready: model={0}, schema={1}" -f $mlHealth.model_type, $mlHealth.feature_schema_version)
    }

    $backendProcess = Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "$backendPort") -WorkingDirectory $backendRoot -PassThru
    if (-not $SkipHealthWait) {
        $backendHealth = Wait-Health "http://127.0.0.1:$backendPort/" { param($body) $body.status -eq "ok" -and $body.ml_service_ready -eq $true }
        Write-Host ("Backend ready: ml_service_status={0}, graph_nodes={1}" -f $backendHealth.ml_service_status, $backendHealth.graph_nodes)
    }
    Write-Host "Backend PID: $($backendProcess.Id)"
    Write-Host "ML adapter PID: $($mlProcess.Id)"
    Write-Host "Stop both processes with: Stop-Process -Id $($backendProcess.Id),$($mlProcess.Id)"
} catch {
    if ($backendProcess) {
        Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Id $mlProcess.Id -Force -ErrorAction SilentlyContinue
    throw
}
