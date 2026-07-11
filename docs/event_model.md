# Event Model

The normalized timeline uses:

- `process_guid`, PID, process name, and command line for process context.
- `timestamp`, `category`, `action`, `object_value`, and `summary` for analyst-facing rows.
- `severity` as display priority, not a detection verdict.
- `raw_json` for drilling back into collector-specific detail.
- `captured_at_utc` as the common cross-collector timestamp. `time` remains the display offset from case start.

Categories currently implemented are Process, API, File, Registry, DNS, Network, Module, Credential, Service, Task, and Snapshot.

Runtime events can currently originate from:

- `ExecutionManager`: process start, exit, timeout, and execution failure
- `Snapshot`: file and registry before/after diff
- `NetworkSnapshot`: new system TCP connections observed after collection
- `Hook`: native JSONL API events plus adapter and transport health events

`CaseData.Quality` contains Runtime, Hook, and ETW status, event/drop counts, messages, network-containment state, process-tree-following state, and the clock source. This metadata is preserved when a case is exported or reopened.
