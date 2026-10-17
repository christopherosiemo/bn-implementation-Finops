param([switch]$NoBuild)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
  node scripts/bootstrap.mjs
  if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed' }
  if ($NoBuild) { docker compose up -d } else { docker compose up --build -d }
  if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed' }
  Write-Host 'Console: http://localhost:3000 · fixture user owner / local-pilot-demo'
  Write-Host 'Readiness: docker compose ps. Acceptance: node scripts/smoke.mjs'
} finally { Pop-Location }
