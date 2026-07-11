# Event Model

The normalized timeline uses:

- `process_guid`, PID, process name, and command line for process context.
- `timestamp`, `category`, `action`, `object_value`, and `summary` for analyst-facing rows.
- `severity` as display priority, not a detection verdict.
- `raw_json` for drilling back into collector-specific detail.

Categories currently implemented are Process, API, File, Registry, DNS, Network, Module, Credential, Service, Task, and Snapshot.

Runtime events can currently originate from:

- `ExecutionManager`: process start, exit, timeout, and execution failure
- `Snapshot`: file and registry before/after diff
- `NetworkSnapshot`: new system TCP connections observed after collection
- `Hook`: reserved for native JSONL hook events
