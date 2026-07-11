# MRTW Architecture

MRTW is split into a shared Core library, a WPF analyst UI, and a CLI entry point.

- `MRTW.Core` owns domain models, static analysis, runtime collection, snapshot diffing, and export packaging.
- `MRTW.App` presents the timeline workbench shown in the reference images.
- `MRTW.Cli` exposes `version`, `doctor`, `static`, `run`, `export`, `batch`, `selftest`, `list`, and `open`.

`AnalysisOrchestrator` is the common GUI/CLI acquisition path. It establishes a shared case ID and UTC epoch, applies fail-closed Windows Firewall containment, runs the managed runtime collector, starts ETW after the root PID is known, follows descendant PIDs, merges telemetry, reruns behavior correlation, and records per-collector quality metadata.

Runtime collection uses standard .NET process execution, file snapshots, HKCU Run/RunOnce registry snapshots, and system TCP snapshots. `case.sqlite` is written through `Microsoft.Data.Sqlite`, so no external `sqlite3.exe` is required. UTC event timestamps and collection quality are preserved across JSON and SQLite round-trips.

`MRTW.Collectors.Etw` contains the TraceEvent-backed collector for Process, ImageLoad, TCP, and DNS events. The CLI exposes `mrtw etw-smoke` for permission and provider checks without requiring a full case run.

Native API hooks under `src/MRTW.Native` use MinHook and emit JSONL through a named pipe. Adapter installation status and an aggregate installation summary are emitted at startup; the managed pipe server also reports received lines, parse failures, and connection failures. Child processes are created suspended by the hook, instrumented, and resumed unless the caller originally requested a suspended process.

Case management is centralized in `CaseService`, and CLI/WPF both use the same JSON/SQLite/export model. Privacy-mode exports are handled by `PrivacyRedactor`.
