$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$templateDir = Join-Path $repoRoot "assets/mcp-server"

Push-Location $templateDir
try {
    npm install --package-lock-only --ignore-scripts
    npm audit --audit-level=high
} finally {
    Pop-Location
}

Write-Host "Refreshed and verified assets/mcp-server/package-lock.json"
