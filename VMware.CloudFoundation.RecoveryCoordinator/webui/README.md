# Recovery Coordinator – cross-platform web UI (spike)

Experimental browser front end that runs on Windows, macOS and Linux (PowerShell 7+). The WPF UI in
`../xaml` is untouched and remains the Windows UI.

```powershell
Import-Module VMware.CloudFoundation.RecoveryCoordinator
Start-VCFRecoveryCoordinatorWeb            # starts 127.0.0.1:<free port>, opens the browser
Start-VCFRecoveryCoordinatorWeb -NoBrowser -Port 8765
```

Use **Quit** in the page to stop the server (or kill the `pwsh` process it started).

## How it works

- `VCFRecoveryCoordinatorWeb.ps1` – single-threaded `HttpListener` server. Reads the same
  `plans/recovery-plan-catalog.json` and plan files as the WPF UI. Everything (HTTP requests, child
  process output) is polled on one thread, so there are no runspaces, events or locks.
- `index.html` – one static page, no dependencies/build step. Output is inserted with `textContent`
  only (ANSI colours converted to spans), never as HTML.
- Each step runs in its own `pwsh -EncodedCommand` child with redirected stdin/stdout/stderr. Shared
  variables are injected as assignments at the top of every step; `secureEncryptionPassword` is wrapped
  in `ConvertTo-SecureString`. `Read-Host` prompts are answered through the input box (stdin).
- Completion uses the process exit code plus the same marker gate as `Test-StepTranscriptClean`
  (`[WARNING]`, `[ERROR]`, `[EXCEPTION]`, `+ CategoryInfo`): `Done`, `Attention` (finished but not
  clean – stops Run All), `Failed`, `Stopped`. Each run is also logged to
  `vcfir-web-<timestamp>-<pid>-<n>.log` in the launch directory.
- Run All honours `threadId` blocks like the WPF UI: consecutive rows with a threadId form a block,
  threads in a block run concurrently, the main sequence continues when all finish cleanly.

## Security

The server executes commands from plan files, so: loopback only; a random per-launch token (in the URL
printed/opened by the cmdlet) is required on every request; `Host` and `Origin` headers are checked
(DNS-rebinding / cross-site); `/api/run` accepts only a plan id + step index, never a command line.
Variable values live in server memory only.

## What matches the WPF UI now

Layout (header, Recovery Parameters / Discovered Infrastructure / Recovery Tasks on the left, Console and
Advisories on the right), Discovered Infrastructure from an extracted-sddc-data.json (domain list filtered per
plan, additional clusters with Storage / Stretched / Dependent On), selection driving `$workloadDomain` and
`$clusterName` and `dataPath` step conditions, Recovery Tasks hidden until something is selected, Variables vs.
Recovery Plan vs. Advanced tabs, the User | Engineering switch (same password gate; Advanced is Engineering only),
plan-specific extra toggles, Save & Exit / Resume, Run Plan with thread blocks and the overall timer.

The console is a persistent `pwsh` on a real pseudo-terminal (xterm.js in the page). Steps reach it through a
private queue directory read by `console-repl.ps1`, not by typing into its stdin: terminal cursor-position replies
and injected text interleave on stdin and corrupted long commands. The consequence: the console answers prompts
(`Read-Host`) but is not a free-typing shell between steps. Ctrl+C ends that console; the page restarts it.

**Browse** is an in-page file browser (`GET /api/fs`), not a native OS dialog: a browser can't hand a page a file's
full path, and driving the native dialogs from the server proved unreliable (focus, screen grabbing, macOS Automation
permission prompts). It lists folders with plain .NET calls, so it behaves the same on Windows (drives, UNC paths),
macOS and Linux. It returns names, sizes and dates only -- never file contents -- for folders the server's account can
already read, behind the same per-launch token as the rest of the API. The `.json` filter is by extension, with a
"Show all files" escape hatch; typing a path into its box also works.

## Not done yet

- **Data Source "Extract SDDC Manager Backup"** only remembers the backup path; the extraction flow (and its
  password prompt) is not ported. Use "Load Extracted SDDC Data".
- Pause points / breakpoints, the "use answer file for interactive tasks" toggle and its auto-answered badges,
  and `Update-SelectedClusterNameFromDisk` (re-resolving the cluster name after `Update-ExtractedSDDCData`).
- The module update banner and credentials-file auto-discovery beyond the Retrieve step hand-off.
- Save & Exit writes `vcfibr-state-<timestamp>.json` to the launch directory (a browser has no native save
  dialog); Resume lists those files.
- **Windows ConPTY (`ConPty.cs`) compiles but has never been run on Windows.** macOS is the only platform this has
  been exercised on. Linux uses the same `script(1)` path as macOS but is untested.
- Passwords entered in the page are held in server memory and handed to a console through a private 0600 file
  that the console deletes immediately; a per-session-key scheme is still needed to replace the Windows DPAPI use.
- The IR module itself still has Windows-only code paths (OVF Tool path, `tar.exe`/registry checks,
  `Resolve-DnsName`, backslash paths); steps that hit them will fail on macOS/Linux until fixed.
