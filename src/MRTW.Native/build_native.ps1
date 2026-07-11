param(
    [string]$Configuration = "Release",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root "build"
cmake -S $root -B $build -A x64
cmake --build $build --config $Configuration

if ($OutputDir -ne "") {
    New-Item -ItemType Directory -Force $OutputDir | Out-Null
    Copy-Item (Join-Path $build "$Configuration\hook_x64.dll") $OutputDir -Force
    Copy-Item (Join-Path $build "$Configuration\injector_x64.exe") $OutputDir -Force
}

