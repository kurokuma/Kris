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

- `SafeRuntimeProbe`: a harmless executable that performs temporary file, HKCU registry, DLL-load, COM init, localhost-only network, and echo child-process actions.
- `SyntheticBehaviorCase`: generates a MRTW `case.json` with synthetic events for dangerous behaviors without executing those behaviors.
- `StaticAnalysisProbe`: a harmless executable that embeds static-analysis markers such as URLs, domains, registry paths, file paths, command strings, and export-like names without executing them.
- `NativeExportProbe`: a harmless DLL that exports `DllRegisterServer`, `Start`, and `Run` for validating PE export table parsing and rundll32 export selection.

Use `SafeRuntimeProbe` as a real target for hook/ETW smoke tests. Use `SyntheticBehaviorCase` for UI, filtering, and behavior-correlation validation.
Use `StaticAnalysisProbe` as a stable target for `mrtw static` and string/classification checks. For this .NET sample, point static analysis at `bin\Release\net9.0\StaticAnalysisProbe.dll`; the generated `.exe` is the .NET apphost and mostly contains host/runtime strings.
