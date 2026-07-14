# MRTW test assets

This folder contains benign validation helpers for MRTW.

## Safety model

- No process injection.
- No persistence installation.
- No credential, browser, wallet, clipboard, screenshot, or keyboard collection.
- No external network communication.
- No service or driver creation.
- File writes are limited to `%TEMP%\MRTW-Probe`.
- Registry writes are limited to `HKCU\Software\MRTW\Probe` and are cleaned up.

## Projects

- `SafeRuntimeProbe`: a harmless executable that performs temporary file, HKCU registry, DLL-load, COM init, loopback HTTP/TCP, UDP, explicit loopback address mapping, and echo child-process actions. It never calls the system DNS resolver. Its cleanup observation JSON is created only beneath `%TEMP%\MRTW-Probe\observations` with a file-name-only argument.
- `SyntheticBehaviorCase`: generates a MRTW `case.json` with synthetic events for dangerous behaviors without executing those behaviors.
- `StaticAnalysisProbe`: a harmless executable that embeds static-analysis markers such as URLs, domains, registry paths, file paths, command strings, and export-like names without executing them.
- `MRTW.RegressionTests`: also creates harmless temporary PS1/VBS/ZIP fixtures for non-PE Initial Access Triage. They validate URL/command-marker extraction, no decode/execute path, ZIP traversal rejection, and JSON/CSV/privacy export integration.
- `NativeExportProbe`: a harmless DLL that exports `DllRegisterServer`, `Start`, and `Run` for validating PE export table parsing and rundll32 export selection.
- `MRTW.RegressionTests`: a dependency-free executable regression suite for P0 orchestration, containment-mode validation, UTC event timestamps, SQLite quality round-trips, and deterministic behavior correlation.
- `MRTW.ProbeTests`: launches the built SafeRuntimeProbe and asserts only loopback HTTP/TCP, UDP, local-only address mapping and cleanup observation. The native direct runner is skipped unless `MRTW_NATIVE_SAFE_PROBE_PATH` explicitly names a built benign binary.
- `Run-CliBatchIntegration.ps1`: runs the built CLI against a benign DLL and a deliberately unreadable EXE with execution disabled. It verifies per-target failure isolation, exit code 10, per-target JSON events plus final summary equivalence, Privacy Mode masking, and rejection of `batch --cmd` before a command or target can run.

Use `SafeRuntimeProbe` as a real target for hook/ETW smoke tests. Use `SyntheticBehaviorCase` for UI, filtering, and behavior-correlation validation.

`MRTW.RegressionTests`には、4つの永続化面（Startup Folder、Scheduled Task、Windows Service、WMI subscription）の安全な合成before/afterデータを用いる差分回帰を含みます。実OSの永続化設定は作成・変更・削除しません。create/modify/delete、面別quality、Artifacts/Behavior相関、Privacy ModeのJSON/SQLite/HTML出力を検証します。
Use `StaticAnalysisProbe` as a stable target for `mrtw static` and string/classification checks. For this .NET sample, point static analysis at `bin\Release\net9.0\StaticAnalysisProbe.dll`; the generated `.exe` is the .NET apphost and mostly contains host/runtime strings.

Run the regression suite with:

```powershell
dotnet run --project test\MRTW.RegressionTests -c Release
dotnet run --project test\MRTW.ProbeTests -c Release
powershell -ExecutionPolicy Bypass -File test\Run-CliBatchIntegration.ps1
```

## Opt-in Windows integration and GUI smoke tests

`Run-IsolatedVmIntegration.ps1` is intentionally gated by `MRTW_ISOLATED_VM=1`, Windows, elevation, and an explicit disposable-VM sentinel file (`%SystemDrive%\MRTW_DISPOSABLE_VM_OK` containing `MRTW_DISPOSABLE_VM=YES`). `block`/`isolated` additionally require `-AllowContainment`. It uses Privacy Mode for retained artifacts and never enables containment by default.

`Run-GuiSmoke.ps1` is intentionally gated by `MRTW_GUI_TESTS=1` and an interactive desktop. It uses built-in UI Automation IDs to verify static-target setup, enabled Start/Stop transitions, non-PE Start-disabled triage selection, terminal stop state, collection-quality visibility, synthetic-case open, and a Privacy Mode export artifact. The gated `--smoke-target`, `--smoke-case`, and `--smoke-export` app arguments exist only for this script. Neither runner is part of normal builds or test commands.
