$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$probe = Join-Path $root 'test\StaticAnalysisProbe\bin\Release\net9.0\StaticAnalysisProbe.dll'
if (-not (Test-Path -LiteralPath $probe)) {
    throw "Build StaticAnalysisProbe first: $probe"
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("MRTW-CliBatch-" + [Guid]::NewGuid().ToString('N'))
try {
    $input = Join-Path $temp 'input'
    $out = Join-Path $temp 'out'
    $summary = Join-Path $temp 'batch-summary.json'
    New-Item -ItemType Directory -Path $input, $out | Out-Null
    $broken = Join-Path $input '01-broken.exe'
    Set-Content -LiteralPath $broken -Value 'not a PE file' -NoNewline
    Copy-Item -LiteralPath $probe -Destination (Join-Path $input '02-good.dll')

    $arguments = @('run', '--project', (Join-Path $root 'src\MRTW.Cli'), '-c', 'Release', '--no-build', '--',
        'batch', '--input', $input, '--out', $out, '--execute', 'off', '--privacy-mode', 'on', '--format', 'json',
        '--summary', $summary, '--log-format', 'json')
    # A sharing violation makes this candidate deterministically unreadable without executing it.
    $lock = [System.IO.File]::Open($broken, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try { $lines = & dotnet @arguments 2>&1 }
    finally { $lock.Dispose() }
    if ($LASTEXITCODE -ne 10) { throw "Expected partial failure exit code 10; got $LASTEXITCODE. Output: $($lines -join [Environment]::NewLine)" }
    $objects = $lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json }
    $completed = @($objects | Where-Object { $_.event -eq 'batch_completed' })
    if ($completed.Count -ne 1) { throw 'Expected exactly one batch_completed JSON event.' }
    $completed = $completed[0]
    $targetEvents = @($objects | Where-Object { $_.event -in @('analysis_completed', 'analysis_failed') })
    if ($targetEvents.Count -ne 2 -or @($targetEvents | Where-Object { $_.event -eq 'analysis_completed' }).Count -ne 1 -or @($targetEvents | Where-Object { $_.event -eq 'analysis_failed' }).Count -ne 1) { throw 'Expected one JSON event for each target.' }
    if ($completed.succeeded -ne 1 -or $completed.failed -ne 1 -or $completed.skipped -ne 0 -or $completed.exit_code -ne 10) { throw 'Unexpected batch aggregate.' }
    if ($completed.items[0].status -ne 'failed' -or $completed.items[1].status -ne 'succeeded') { throw 'A failed target did not remain isolated from the following target.' }
    $saved = Get-Content -LiteralPath $summary -Raw | ConvertFrom-Json
    if (($saved | ConvertTo-Json -Depth 8 -Compress) -ne (($completed | Select-Object completed_at_utc, succeeded, failed, skipped, exit_code, items) | ConvertTo-Json -Depth 8 -Compress)) { throw 'Summary JSON does not match batch_completed payload.' }
    $leak = @($lines | Out-String) + (Get-Content -LiteralPath $summary -Raw)
    foreach ($secret in @($input, $out, '01-broken.exe', '02-good.dll')) {
        if ($leak -match [regex]::Escape($secret)) { throw "Privacy Mode leaked batch detail: $secret" }
    }
    $marker = Join-Path $temp 'batch-cmd-must-not-run.txt'
    $cmdOut = Join-Path $temp 'cmd-out'
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $cmdLines = & dotnet run --project (Join-Path $root 'src\MRTW.Cli') -c Release --no-build -- batch --input $input --out $cmdOut --cmd "cmd.exe /c echo blocked > $marker" --log-format json 2>&1
        $cmdExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorAction }
    if ($cmdExitCode -ne 1) { throw "Expected --cmd input rejection exit code 1; got $cmdExitCode." }
    if (Test-Path -LiteralPath $marker) { throw 'batch --cmd executed a command despite rejection.' }
    if (Test-Path -LiteralPath $cmdOut) { throw 'batch --cmd started target processing despite rejection.' }
    if (($cmdLines | Out-String) -notmatch 'does not support --cmd') { throw 'batch --cmd rejection did not explain the containment boundary.' }
    Write-Host 'PASS CLI batch integration'
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
