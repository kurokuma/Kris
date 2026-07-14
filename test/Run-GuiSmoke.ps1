[CmdletBinding()]
param(
    [string]$Target,
    [string]$Case,
    [string]$NonPeTarget
)

$ErrorActionPreference = 'Stop'
if ($env:MRTW_GUI_TESTS -ne '1') { throw 'Refusing to run: set MRTW_GUI_TESTS=1 on an interactive desktop.' }
if (-not [Environment]::UserInteractive) { throw 'GUI smoke test requires an interactive Windows desktop.' }
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Target)) { $Target = Join-Path $PSScriptRoot 'StaticAnalysisProbe\bin\Release\net9.0\StaticAnalysisProbe.dll' }
if ([string]::IsNullOrWhiteSpace($NonPeTarget)) { $NonPeTarget = Join-Path ([IO.Path]::GetTempPath()) ('mrtw-nonpe-smoke-' + [guid]::NewGuid().ToString('N') + '.ps1'); Set-Content -LiteralPath $NonPeTarget -Value "# harmless GUI smoke fixture`nhttps://example.invalid/" -NoNewline }
if ([string]::IsNullOrWhiteSpace($Case)) { $Case = Join-Path $PSScriptRoot 'synthetic-gui-case\case.json' }
if (-not (Test-Path -LiteralPath $Target)) { throw "Target missing: $Target" }
$app = Join-Path $root 'src\MRTW.App\bin\Release\net9.0-windows\MRTW.App.exe'
if (-not (Test-Path -LiteralPath $app)) { throw "App missing: build Release first ($app)." }

Add-Type -AssemblyName UIAutomationClient
$caseRoot = Split-Path -Parent $Case
if (-not (Test-Path -LiteralPath $Case)) {
    New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
    dotnet run --project (Join-Path $PSScriptRoot 'SyntheticBehaviorCase') -c Release -- $caseRoot
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Case)) { throw 'Could not create the benign synthetic GUI case.' }
}

function Get-WindowElement([Diagnostics.Process]$Process) {
    $deadline = (Get-Date).AddSeconds(20)
    $sawWindowHandle = $false
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'MRTW process exited before its GUI window became available.' }

        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) {
            $sawWindowHandle = $true
            try { $element = [System.Windows.Automation.AutomationElement]::FromHandle($handle) }
            catch { $element = $null }
            if ($null -ne $element) { return $element }
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    $Process.Refresh()
    if ($Process.HasExited) { throw 'MRTW process exited before its GUI window became available.' }
    if (-not $sawWindowHandle) { throw 'MRTW window handle was not available within 20 seconds.' }
    throw 'MRTW window handle was available, but its UI Automation root could not be obtained within 20 seconds.'
}
function Find-Id($Element, [string]$Id) {
    return $Element.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)))
}
function Close-App([Diagnostics.Process]$Process) { if (-not $Process.HasExited) { $Process.CloseMainWindow() | Out-Null; Start-Sleep -Milliseconds 500; if (-not $Process.HasExited) { $Process.Kill() } } }

$proc = Start-Process -FilePath $app -ArgumentList @('--smoke-target', $Target) -PassThru
try {
    $rootElement = Get-WindowElement $proc; $start = Find-Id $rootElement 'StartAnalysisButton'; $stop = Find-Id $rootElement 'StopAnalysisButton'; $timeline = Find-Id $rootElement 'TimelineGrid'; $sample = Find-Id $rootElement 'CurrentSampleText'; $quality = Find-Id $rootElement 'CollectionQualityText'; $normalizedCommands = Find-Id $rootElement 'NormalizedCommandsGrid'
    if ($null -eq $start -or $null -eq $stop -or $null -eq $timeline -or $null -eq $normalizedCommands) { throw 'Required UI Automation identifiers were not found.' }
    if (-not $start.Current.IsEnabled -or $sample.Current.Name -notmatch 'StaticAnalysisProbe') { throw 'Static target selection was not reflected in the UI.' }
    $pattern = $start.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern); ([System.Windows.Automation.InvokePattern]$pattern).Invoke()
    $deadline = (Get-Date).AddSeconds(10); do { Start-Sleep -Milliseconds 250 } while (-not $stop.Current.IsEnabled -and (Get-Date) -lt $deadline)
    if (-not $stop.Current.IsEnabled) { throw 'Start did not enter a stoppable analysis state.' }
    ([System.Windows.Automation.InvokePattern]$stop.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
    $deadline = (Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } while ($stop.Current.IsEnabled -and (Get-Date) -lt $deadline)
    if ($stop.Current.IsEnabled) { throw 'Stop did not reach a terminal state.' }
    if ([string]::IsNullOrWhiteSpace($quality.Current.Name)) { throw 'Collection quality was not displayed.' }
    Write-Host 'PASS GUI runtime: static selection, Start/Stop terminal state, timeline control and quality visibility.'
}
finally { Close-App $proc }

$nonPeProc = Start-Process -FilePath $app -ArgumentList @('--smoke-target', $NonPeTarget) -PassThru
try {
    $nonPeWindow = Get-WindowElement $nonPeProc; $nonPeStart = Find-Id $nonPeWindow 'StartAnalysisButton'; $nonPeSample = Find-Id $nonPeWindow 'CurrentSampleText'
    $deadline = (Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } while (($nonPeSample.Current.Name -notmatch 'mrtw-nonpe-smoke' -or $nonPeStart.Current.IsEnabled) -and (Get-Date) -lt $deadline)
    if ($nonPeSample.Current.Name -notmatch 'mrtw-nonpe-smoke' -or $nonPeStart.Current.IsEnabled) { throw 'Non-PE target was not reflected as a read-only, Start-disabled triage target.' }
    Write-Host 'PASS GUI non-PE: target is shown and Start is disabled.'
}
finally { Close-App $nonPeProc; if (Test-Path -LiteralPath $NonPeTarget) { Remove-Item -LiteralPath $NonPeTarget -Force } }

$exportRoot = Join-Path ([IO.Path]::GetTempPath()) ('mrtw-gui-export-' + [guid]::NewGuid().ToString('N'))
$caseProc = Start-Process -FilePath $app -ArgumentList @('--smoke-case', $Case, '--smoke-export', $exportRoot) -PassThru
try {
    $caseWindow = Get-WindowElement $caseProc; $sample = Find-Id $caseWindow 'CurrentSampleText'; $timeline = Find-Id $caseWindow 'TimelineGrid'
    $deadline = (Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } while (($sample.Current.Name -notmatch 'synthetic-sample' -or $timeline.Current.BoundingRectangle.IsEmpty) -and (Get-Date) -lt $deadline)
    if ($sample.Current.Name -notmatch 'synthetic-sample') { throw 'Synthetic case was not opened.' }
    if (-not (Get-ChildItem -LiteralPath $exportRoot -Recurse -Filter case.json -ErrorAction SilentlyContinue)) { throw 'GUI smoke export did not produce case.json.' }
    Write-Host 'PASS GUI case: synthetic case opened and privacy-mode export artifact created.'
}
finally { Close-App $caseProc; if (Test-Path -LiteralPath $exportRoot) { Remove-Item -LiteralPath $exportRoot -Recurse -Force } }
