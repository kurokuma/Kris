[CmdletBinding()]
param(
    [ValidateSet('observe', 'block', 'isolated')]
    [string]$NetworkMode = 'observe',
    [switch]$AllowContainment,
    [string]$DisposableVmSentinel
)

$ErrorActionPreference = 'Stop'
if ($env:MRTW_ISOLATED_VM -ne '1') { throw 'Refusing to run: set MRTW_ISOLATED_VM=1 in a disposable isolated Windows VM.' }
if (-not $IsWindows) { throw 'This integration test requires Windows.' }
$systemDrive = if ([string]::IsNullOrWhiteSpace($env:SystemDrive)) { 'C:' } else { $env:SystemDrive }
if ([string]::IsNullOrWhiteSpace($DisposableVmSentinel)) { $DisposableVmSentinel = Join-Path $systemDrive 'MRTW_DISPOSABLE_VM_OK' }
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test from an elevated PowerShell session.' }
if (-not (Test-Path -LiteralPath $DisposableVmSentinel) -or (Get-Content -Raw -LiteralPath $DisposableVmSentinel).Trim() -ne 'MRTW_DISPOSABLE_VM=YES') { throw "Refusing to run: create the explicit disposable-VM sentinel $DisposableVmSentinel containing MRTW_DISPOSABLE_VM=YES." }
if ($NetworkMode -ne 'observe' -and -not $AllowContainment) { throw 'Refusing containment mode: pass -AllowContainment only after validating the disposable VM. This may change Windows Firewall rules during the test.' }

$root = Split-Path -Parent $PSScriptRoot
$probe = Join-Path $root 'test\SafeRuntimeProbe\bin\Release\net9.0\SafeRuntimeProbe.exe'
if (-not (Test-Path -LiteralPath $probe)) { throw "SafeRuntimeProbe not found: build the solution first ($probe)." }
$out = Join-Path ([IO.Path]::GetTempPath()) ('mrtw-isolated-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null

try {
    dotnet run --project (Join-Path $root 'src\MRTW.Cli') -c Release -- run --target $probe --duration 8 --network $NetworkMode --privacy-mode on --out $out --format json,sqlite
    if ($LASTEXITCODE -ne 0) { throw "MRTW CLI failed with exit code $LASTEXITCODE." }
    $case = Get-ChildItem -LiteralPath $out -Recurse -Filter case.json | Select-Object -First 1
    if ($null -eq $case) { throw 'case.json was not exported.' }
    $data = Get-Content -Raw -LiteralPath $case.FullName | ConvertFrom-Json
    if ($null -eq $data.quality) { throw 'Collection Quality is missing.' }
    if ($data.quality.collectors.Count -eq 0) { throw 'No collector quality entries were recorded.' }
    if ($NetworkMode -eq 'observe' -and $data.quality.network_containment -ne 'observe') { throw 'Observe mode quality did not report observe.' }
    if ($NetworkMode -ne 'observe' -and $data.quality.network_containment -notmatch 'block|isolated') { throw 'Containment mode quality was not recorded.' }
    $runtime = @($data.quality.collectors | Where-Object { $_.collector -eq 'Runtime' })
    if ($runtime.Count -ne 1 -or $runtime[0].status -notmatch 'healthy|degraded') { throw 'Runtime collector health was not recorded as healthy/degraded.' }
    $etw = @($data.quality.collectors | Where-Object { $_.collector -eq 'ETW' })
    if ($etw.Count -ne 1) { throw 'ETW collector health was not recorded.' }
    if ($etw[0].status -match 'skipped|failed|unavailable') {
        Write-Host "SKIP ETW capture assertions: collector status=$($etw[0].status), message=$($etw[0].message)"
    } else {
        $etwEvents = @($data.events | Where-Object { $_.source -match 'ETW' })
        if ($etwEvents.Count -eq 0) { throw 'ETW reported available but no ETW-sourced event was exported.' }
        if (-not ($etwEvents | Where-Object { $_.action -match 'Process Start|Process Exit' })) { throw 'ETW reported available but did not observe the probe process lifecycle.' }
    }
    if (-not ($data.events | Where-Object { $_.source -eq 'ExecutionManager' -and $_.action -eq 'Process Start' })) { throw 'Runtime process start was not recorded.' }
    if (-not ($data.events | Where-Object { $_.source -eq 'Snapshot' -and $_.action -match 'Snapshot Bounded' })) { throw 'Before/after snapshot evidence was not recorded.' }
    if (-not ($data.events | Where-Object { $_.object -match 'MRTW SafeRuntimeProbe child process|cmd.exe' })) { Write-Warning 'Child-process event was not directly captured; inspect ETW availability/coverage before treating this as a collector defect.' }
    if ($NetworkMode -ne 'observe') {
        $leftoverRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -like 'MRTW-*' })
        if ($leftoverRules.Count -gt 0) { throw "Containment cleanup failed: $($leftoverRules.DisplayName -join ', ')" }
    }
    Write-Host "PASS isolated VM integration: $($case.FullName)"
    Write-Host 'Expected: Runtime health and snapshot evidence are required; unavailable ETW is explicitly SKIP, while healthy ETW must export lifecycle events. Retained artifacts use Privacy Mode and remain under the temp output path for review.'
}
finally {
    Write-Host "Artifacts retained for analyst review: $out"
}
