param([switch]$NoBuild)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
  node scripts/bootstrap.mjs
  if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed' }
  if (-not $NoBuild) {
    docker compose build minio
    if ($LASTEXITCODE -ne 0) { throw 'Object-store build failed' }
    docker compose build buckets
    if ($LASTEXITCODE -ne 0) { throw 'Object-store client build failed' }
    docker compose build api economics web
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed' }
  }
  docker compose up --no-build -d
  if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed' }
  Write-Host 'Console: http://localhost:3000 · fixture user owner / local-pilot-demo'
  Write-Host 'Readiness: docker compose ps. Acceptance: node scripts/smoke.mjs'
} finally { Pop-Location }
