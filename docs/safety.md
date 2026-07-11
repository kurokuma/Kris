# Safety

The WPF UI does not execute selected samples by default. It performs static analysis and safe snapshot collection for inspection.

The CLI `run` command can execute a target or command line. Use it only inside an isolated VM with snapshots and explicit network controls. For inspection without execution, pass:

```powershell
--execute off
```

Timeout handling defaults to killing the target process tree. Use `--timeout-action stop` to stop collection without killing the target.

ETW and native hook validation should still be performed in an isolated VM. The codebase can build these components without that VM, but correctness and safety validation require a controlled Windows environment.
