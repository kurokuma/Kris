# MRTW Native Components

This folder contains the native injector and hook DLL described by the README.

MinHook is resolved by CMake FetchContent and used by `hook_x64.dll`.

Expected future build environment:

- MSVC x64
- C++20
- `/EHsc`
- Windows SDK

- `injector`: target launch and DLL injection entry point
- `hook`: DLL entry point, pipe client, and API hook adapters

Build:

```powershell
.\build_native.ps1 -Configuration Release -OutputDir ..\MRTW.Cli\bin\Release\net9.0\native
```
