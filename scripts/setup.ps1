$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
python -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
& .\.venv\Scripts\python.exe -m pip install -r requirements.lock
if ($LASTEXITCODE -ne 0) { throw 'Python dependencies failed' }
npm ci
if ($LASTEXITCODE -ne 0) { throw 'Node dependencies failed' }
npm run build
if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
Write-Host 'Beaver is ready. Run npm start.'
