# Build

```powershell
$env:DOTNET_CLI_HOME = "$PWD\.dotnet-home"
dotnet restore MRTW.sln --configfile NuGet.Config
dotnet build MRTW.sln --no-restore
```

WPF builds may need permission to read the installed Windows SDK metadata.

Run the CLI:

```powershell
dotnet run --project src\MRTW.Cli -- run --target src\MRTW.Cli\bin\Debug\net9.0\MRTW.Cli.dll --duration 5 --out out\cases --format all
```

Run without executing the target:

```powershell
dotnet run --project src\MRTW.Cli -- run --target C:\Samples\sample.exe --execute off --out out\cases --format all
```

Use profile/config/export controls:

```powershell
dotnet run --project src\MRTW.Cli -- run --target C:\Samples\sample.exe --profile full-capture --privacy-mode on --auto-suffix
dotnet run --project src\MRTW.Cli -- export --case out\cases\<case>\case.sqlite --format all --privacy-mode on --out out\exports
```

Verify SQLite output when `sqlite3` is installed:

```powershell
sqlite3 out\cases\<case>\case.sqlite ".tables"
```

Check ETW collector availability:

```powershell
dotnet run --project src\MRTW.Cli -- etw-smoke --duration 3
```

Some ETW providers require administrator privileges. A non-admin failure from `etw-smoke` is expected on locked-down systems.

Build native hook/injector binaries:

```powershell
cmake --preset msvc-x64 -S src\MRTW.Native
cmake --build --preset msvc-x64-release
```

When `hook_x64.dll` and `injector_x64.exe` exist under the native CMake output directory, the WPF/CLI projects copy them into `native\` below their output directory.
