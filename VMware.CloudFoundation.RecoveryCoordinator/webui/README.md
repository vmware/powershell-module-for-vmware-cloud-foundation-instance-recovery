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

## Not done yet (known gaps vs the WPF UI)

- **No persistent console.** A fresh `pwsh` per step: anything a step leaves in session state
  (e.g. `$credentialsFilePath` via `Set-VCFCredentialsFilePath`, PowerCLI connections) is not carried to
  the next step. Needs either a long-lived child per thread or explicit state hand-off.
- No real terminal (no PTY / xterm.js): programs that need a TTY, or raw key handling, won't work.
- Not ported: recovery-target selection (workload domain / cluster from the extracted data),
  `dataPath` conditions (fail open, so those steps always show), data-source panel (extract backup /
  load extracted data), breakpoints / pause-after-step, auto-answer badges, engineering mode,
  module update banner, credentials-file discovery.
- Passwords entered in the page are held in server memory and written into the child's startup
  script; a per-session-key scheme is needed to replace the Windows DPAPI use before this is a real
  replacement (see `ConvertFrom-VCFIRProtectedString`).
- The IR module itself still has Windows-only code paths (OVF Tool path, `tar.exe`/registry checks,
  `Resolve-DnsName`, backslash paths); steps that hit them will fail on macOS/Linux until fixed.
