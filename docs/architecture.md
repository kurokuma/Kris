# MRTW Architecture

MRTW is split into a shared Core library, a WPF analyst UI, and a CLI entry point.

- `MRTW.Core` owns domain models, static analysis, runtime collection, snapshot diffing, and export packaging.
- `MRTW.App` presents the timeline workbench shown in the reference images.
- `MRTW.Cli` exposes `version`, `doctor`, `static`, `run`, `export`, `batch`, `selftest`, `list`, and `open`.

Runtime collection uses standard .NET process execution, file snapshots, HKCU Run/RunOnce registry snapshots, and system TCP snapshots. `case.sqlite` is written through `Microsoft.Data.Sqlite`, so no external `sqlite3.exe` is required.

`MRTW.Collectors.Etw` contains the TraceEvent-backed collector for Process, ImageLoad, TCP, and DNS events. The CLI exposes `mrtw etw-smoke` for permission and provider checks without requiring a full case run.

Native API hooks are scaffolded under `src/MRTW.Native`. Adding MinHook later should only require filling the hook adapters and wiring their JSONL pipe stream into the managed event normalizer.

Case management is centralized in `CaseService`, and CLI/WPF both use the same JSON/SQLite/export model. Privacy-mode exports are handled by `PrivacyRedactor`.
