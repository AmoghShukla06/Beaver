# Run cargo inside the Visual Studio developer environment (rustc does not always locate newer VS installs).
# Usage: powershell -File scripts/cargo.ps1 build --release
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio C++ build tools were not found" }
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$service = Join-Path (Split-Path -Parent $PSScriptRoot) "service"
cmd /c "`"$vcvars`" >nul 2>&1 && cd /d `"$service`" && cargo $args"
exit $LASTEXITCODE
