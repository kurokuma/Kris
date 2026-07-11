# UI Spec

The WPF app follows the supplied reference images:

- left rail: recent cases, process tree, and filters
- center: unified timeline with normalized events
- lower center: artifacts, network, files, registry, API raw, and report tabs
- right rail: selected event details and export options
- footer: monitoring state and case counters

The UI ships with realistic default data, can load a selected EXE/DLL target for safe static/snapshot analysis, can open an existing `case.json` or `case.sqlite` bundle, and exports the current case through the shared Core exporter.
