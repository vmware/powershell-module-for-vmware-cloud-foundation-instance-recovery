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

Layout (header, Recovery Parameters / Discovered Infrastructure / Recovery Tasks on the left, Console and Advisories on the
right) and the row/switch/tab styling; Discovered Infrastructure from an extracted-sddc-data.json; selection driving
`$workloadDomain`/`$clusterName` and `dataPath` step conditions; Recovery Tasks hidden until something is selected; the
Variables tab (empty until a variables file is loaded -- validated against the plan's template -- or created with Save As;
every edit is written back to that file); the interactive answer file switch with "Auto Answered" badges; the
engineering-only gate on the FDR type / Recover Fleet plan; the User | Engineering switch with Advanced and pause points
(click a Pending step to insert an "Engineering Break Point"); the backup-encryption-password prompt; the update banner;
Save & Exit / Resume (including the answer file); Run Plan with thread blocks, the overall timer and the WPF messages.

Consoles are plain `pwsh` hosts (see below) fed by a queue; the web server also exits by itself after 10 minutes with no
browser connected and nothing running (`-IdleTimeoutMinutes`), the equivalent of closing the WPF window.

**Browse** is an in-page file browser (`GET /api/fs`), not a native OS dialog: a browser can't hand a page a file's
full path, and driving the native dialogs from the server proved unreliable (focus, screen grabbing, macOS Automation
permission prompts). It lists folders with plain .NET calls, so it behaves the same on Windows (drives, UNC paths),
macOS and Linux, always opens in the launch folder, and doubles as Save As. It returns names, sizes and dates only --
never file contents -- for folders the server's account can already read, behind the same per-launch token as the rest of
the API. The `.json` filter is by extension, with a "Show all files" escape hatch.

## Console backends

`-ConsoleBackend Auto|Pty|Pipe`. **Pipe** (the default on Windows) is a plain `pwsh` with redirected input and output:
steps arrive through a file queue (`console-repl.ps1`), so nothing is typed into a shell, and the only input is answers to
prompts, which the page echoes itself. **Pty** (the default on macOS/Linux) puts that same queue-driven `pwsh` on a real
pseudo-terminal (`script(1)`; ConPTY on Windows, which has never been run). A plain *interactive* `pwsh` under xterm.js was
tried and rejected: its cursor-position round trips interleave with injected text and corrupt it, and bracketed paste is
not honoured. Consequence either way: the console answers prompts but is not a free-typing shell between steps, and
Ctrl+C ends the console (the page restarts it).

## Not done yet

- **Free typing between steps.** Proposed: the page acts as the command line while a console is idle and sends the line
  through the same queue (same session, no input race). Not built.
- **"Extract SDDC Manager Backup"** runs `New-ExtractDataFromSDDCBackup` in the Main console, but that cmdlet still calls
  `Resolve-DnsName` (10 times), which does not exist on macOS/Linux, so extraction is expected to fail there. It has
  never run against a real backup. Use "Load Extracted SDDC Data" for now.
- **Windows and Linux are untested** (macOS is the only platform exercised): the Pipe backend on Windows, the ConPTY
  code, `script(1)` on Linux, the Windows drive/UNC handling in the file browser.
- The InstanceRecovery module itself still has Windows-only code (OVF Tool path, `tar.exe`/registry checks,
  `Resolve-DnsName`, backslash paths); steps that hit them will fail on macOS/Linux.
- A file created with "New Variables File" holds only the names the plan's steps reference, while the shipped template
  also lists names no step references (e.g. `rootUserPassword`), so loading that file back fails the structure check
  (by reading the WPF code, it does the same there).
- Passwords entered in the page are held in server memory and handed to a console through a private 0600 file that the
  console deletes immediately; `Read-Host` echoes an answer back in plain text after Enter.
