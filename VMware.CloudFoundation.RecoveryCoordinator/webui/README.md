# Recovery Coordinator – cross-platform web UI (spike)

Experimental browser front end that runs on Windows, macOS and Linux (PowerShell 7+). The WPF UI in
`../xaml` is untouched and remains the Windows UI.

```powershell
Import-Module VMware.CloudFoundation.RecoveryCoordinator
Start-VCFRecoveryCoordinatorWeb            # starts 127.0.0.1:<free port>, opens the browser
Start-VCFRecoveryCoordinatorWeb -NoBrowser -Port 8765
```

**Closing the window ends the session**, as it does in the WPF UI: about 3 seconds after the last window goes away (`-CloseGraceSeconds`; it only has to outlast a delayed
poll or a console reconnecting) the server exits and takes every console, and anything still running in them, with it. **Save & Exit**
saves a state file first. Closing the window while a step is running asks for confirmation. If no window is ever opened (`-NoBrowser`, or the
browser failed to start) the server exits after 10 minutes (`-IdleTimeoutMinutes`). Several instances can run at once, each with its own
launch folder.

## How it works

- `VCFRecoveryCoordinatorWeb.ps1` – single-threaded `HttpListener` server. Reads the same
  `plans/recovery-plan-catalog.json` and plan files as the WPF UI. Everything (HTTP requests, child
  process output) is polled on one thread, so there are no runspaces, events or locks.
- `index.html` – one static page, no dependencies/build step. Output is inserted with `textContent`
  only (ANSI colours converted to spans), never as HTML.
- Steps run in persistent consoles (Main Thread, Thread 2, ...), each a `pwsh` the server keeps for the whole session, so
  variables, loaded modules and connections carry from step to step (see Console backends). Shared variables are injected as
  assignments before each step; `secureEncryptionPassword` is wrapped in `ConvertTo-SecureString`.
- A step is finished when its console transcript shows `Completed Task <cmdlet>` and the same marker gate as
  `Test-StepTranscriptClean` passes (no `[WARNING]`, `[ERROR]`, `[EXCEPTION]`, `+ CategoryInfo`): `Done`, otherwise `Failed`
  (which stops Run Plan). Each console's transcript is logged to `vcfir-web-transcript-<timestamp>-<pid>-<n>.log` in the
  launch directory.
- Run All honours `threadId` blocks like the WPF UI: consecutive rows with a threadId form a block,
  threads in a block run concurrently, the main sequence continues when all finish cleanly. The server drives it (see below).

## State and the window

The server, not the page, holds the session state, so a **reload** of the window (Ctrl+R, or a browser tab if the default browser isn't Chromium) loses nothing as long as it reconnects within the grace period:

- step statuses, the pause point, the Advisories log, the Overall Recovery Time, the selected plan and data source, and the
  extra toggles are redrawn from the server when the page reconnects;
- **Run Plan runs on the server** (it starts each step, watches the console for completion, walks the thread blocks), so a
  reload does not interrupt it. A step that needs the backup password waits until a window is there to ask for it;
- the consoles keep running and replay their scrollback.

None of this outlives the window: with the window closed the server and its consoles are gone (see above), so there is no headless
instance to reconnect to. Only one window may drive a server at a time: each window has an id (kept in `sessionStorage`, so a
reload is the same window), and a second window is refused ("Already open in another window") until the first closes.

The window opens in its own window of the default browser: an app-style window (no tabs or address bar, the page's own icon) for
Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera, Chromium), a new window for Firefox, and the ordinary open-URL
behaviour for anything else (Safari, unknown). Chromium browsers are started with a small profile of their own
(`~/.vcfir-webui/browser-profile`, no sign-in, no extensions), which keeps the window free of the signed-in profile's badge and
separate from the person's other browser windows. The page icon is the official mark as 32/64/256 px PNGs. On macOS the Dock still
shows the browser's icon for an app-style window; a custom Dock icon would need a real .app wrapper, which this does not build.

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
not honoured. Consequence either way: while a step runs the console only answers prompts, and Ctrl+C ends the console
(the page restarts it).

## Command line between steps (troubleshooting)

When a console is idle (nothing running or queued) the page draws a `PS <folder>>` prompt and acts as the command line.
Each line you press Enter on is sent through the same queue as a step, so it runs in the console's own session: the same
variables (`$workloadDomain`, `$clusterName`, anything the steps set), loaded modules and connections. `Set-Location`
carries over to the prompt. Up/Down recall history, Left/Right/Home/End/Delete edit the line, Ctrl+C abandons it.

Limits: no Tab completion or syntax colouring (the line editor is in the page, not PSReadLine); a line typed in the instant a
step starts is discarded; Ctrl+C while a step is running still ends the console. This widens what the API will execute
(`POST /api/console/exec` takes arbitrary text, still behind the per-launch token and Host/Origin checks), so
`Start-VCFRecoveryCoordinatorWeb -DisableCommandLine` turns it off (the endpoint then returns 403 and the page shows no prompt).

## Not done yet

- **"Extract SDDC Manager Backup"** now avoids the Windows-only parts: `Resolve-DnsName` is wrapped by
  `Resolve-VCFIRHostAddress` (uses it where it exists, the .NET resolver elsewhere -- which also honours the hosts file),
  and the file paths in `New-ExtractDataFromSDDCBackup` use `/` instead of `\`. Verified on macOS only as far as
  decrypt + extract of a synthetic backup (OpenSSL 3 and LibreSSL, folder with a space); it has never run against a real
  backup, and needs `openssl` and `tar` on the PATH.
- **Windows and Linux are untested** (macOS is the only platform exercised): the Pipe backend on Windows, the ConPTY
  code, `script(1)` on Linux, the Windows drive/UNC handling in the file browser.
- The InstanceRecovery module itself still has Windows-only code (OVF Tool path, `tar.exe`/registry checks,
  `Resolve-DnsName`, backslash paths); steps that hit them will fail on macOS/Linux.
- A file created with "New Variables File" holds only the names the plan's steps reference, while the shipped template
  also lists names no step references (e.g. `rootUserPassword`), so loading that file back fails the structure check
  (by reading the WPF code, it does the same there).
- Passwords entered in the page are held in server memory and handed to a console through a private 0600 file that the
  console deletes immediately; `Read-Host` echoes an answer back in plain text after Enter.
