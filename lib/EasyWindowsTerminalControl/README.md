# Vendored: EasyWindowsTerminalControl

Pre-built binaries used by `Start-InstanceRecoveryUI` (in the module's `.psm1`) to embed a
real-terminal-fidelity console in the orchestrator UI, loaded at runtime via `Add-Type -Path` — no
build step or .NET SDK required by end users of the module.

## Files and where they came from

| File | Source package | Version |
|---|---|---|
| `EasyWindowsTerminalControl.dll` | [`EasyWindowsTerminalControl`](https://www.nuget.org/packages/easywindowsterminalcontrol/) (nuget.org) | 1.0.38 |
| `Microsoft.Terminal.Wpf.dll` | `ci.microsoft.terminal.wpf` (see below) | 1.25.260303002 |
| `Microsoft.Terminal.Control.dll` | `ci.microsoft.terminal.wpf`, `runtimes\win-x64\native\` (the actual native rendering engine) | 1.25.260303002 |
| `conpty.dll` | `Microsoft.Windows.Console.ConPTY`, `runtimes\win-x64\native\` (native pseudoconsole implementation `Microsoft.Terminal.Control.dll` depends on) | 1.24.260710001 |

`conpty.dll` was missing from this folder for a while, which is why the embedded terminal never
worked: `Microsoft.Terminal.Control.dll` loads fine without it, and the control object itself
constructs without error, but its internal ConPTY session silently fails to start, leaving
`ConPTYTerm` non-null while any actual use of it (e.g. `WriteToTerm`) throws a
`NullReferenceException`. Both are transitive dependencies of `EasyWindowsTerminalControl` -- see
its `.nuspec` in the NuGet cache for exact versions if these ever need to move.

`ci.microsoft.terminal.wpf` is a **CI/beta-channel package**, not one Microsoft publishes to nuget.org
under its normal name — [EasyWindowsTerminalControl's own README](https://github.com/mitchcapper/EasyWindowsTerminalControl)
describes its WPF support as "not yet publicly packaged." Only Windows x64 native binaries are
vendored here (win-arm64/win-x86 exist in the source package but aren't shipped).

## Regenerating these files

```powershell
dotnet new console -n _tmp --force
cd _tmp
dotnet add package EasyWindowsTerminalControl --version 1.0.38
dotnet build

Copy-Item bin\Debug\net*\EasyWindowsTerminalControl.dll ..\lib\EasyWindowsTerminalControl\
Copy-Item bin\Debug\net*\Microsoft.Terminal.Wpf.dll ..\lib\EasyWindowsTerminalControl\
Copy-Item "$env:USERPROFILE\.nuget\packages\ci.microsoft.terminal.wpf\<version>\runtimes\win-x64\native\Microsoft.Terminal.Control.dll" ..\lib\EasyWindowsTerminalControl\
Copy-Item "$env:USERPROFILE\.nuget\packages\microsoft.windows.console.conpty\<version>\runtimes\win-x64\native\conpty.dll" ..\lib\EasyWindowsTerminalControl\
```
(`<version>` — check `dir "$env:USERPROFILE\.nuget\packages\ci.microsoft.terminal.wpf"` /
`dir "$env:USERPROFILE\.nuget\packages\microsoft.windows.console.conpty"` for whatever versions
actually resolved.) `dotnet build` alone does **not** copy either native DLL because the project has
no `RuntimeIdentifier` set — that's why both have to be pulled from the NuGet cache by hand rather
than just copying everything from a build output folder. Don't skip `conpty.dll` -- see above.
