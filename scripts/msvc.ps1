# Run a command inside the Visual Studio developer environment (rustc does not always locate newer VS installs).
# Usage: powershell -File scripts/msvc.ps1 cargo build --release
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio C++ build tools were not found" }
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$root = Split-Path -Parent $PSScriptRoot
cmd /c "`"$vcvars`" >nul 2>&1 && cd /d `"$root`" && $args"
exit $LASTEXITCODE
