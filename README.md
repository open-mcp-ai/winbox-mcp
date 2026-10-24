# winbox-mcp

A zero-install MCP server that turns a Windows host into **structured answers
instead of terminal text**.

Point an MCP client at it and ask a question — *what is this machine, what is
filling the disk, what is listening on port 443, which auto-start service is
down* — and get one typed JSON answer per question, with a one-screen summary for
the human reading the transcript.

```
$ pwsh -NoProfile -File winbox-mcp.ps1 -RunTool volumes
{
  "Summary": "C:              NTFS     33.1 GB free of    49.9 GB (66%)",
  "Data": { "volumes": [ { "letter": "C:", "free_percent": 66, ... } ], ... }
}

$ $env:WINBOX_ARGS = '{"top":5,"sort":"cpu"}'    # arguments, quoting-free
$ pwsh -NoProfile -File winbox-mcp.ps1 -RunTool processes
```

`-ArgsJson '{"top":5}'` also works, but Windows PowerShell 5.1 mangles the quotes
of a JSON argument on its way to a native command, so the environment variable is
the form that always survives.

## Why this exists

An agent driving Windows over a shell spends its turns on PowerShell
archaeology: writing the WMI query, surviving the quoting, and then parsing a
formatted table back into facts. Three round trips to answer one question, and
every host it touches is a fresh guess.

| the question | the old way | with winbox-mcp |
| --- | --- | --- |
| what is listening, and who owns it | `netstat -ano`, then map pids by hand | `listening_ports` |
| is a disk failing | `Get-PhysicalDisk` + `Get-Disk` + guesswork | `volumes` |
| why is this host broken | `Get-Service \| Where-Object Status -eq Stopped` | `services` → `auto_start_but_stopped` |
| what is eating memory | `Get-Process \| Sort WS -Desc`, re-read as text | `resources` |
| what is this machine | five commands, four of them CIM | `host_info` |

## Install

There is nothing to install. Windows PowerShell 5.1 ships with every supported
Windows, and this server is a single file.

```powershell
# copy winbox-mcp.ps1 to the host, then:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\tools\winbox-mcp.ps1 -SelfTest
```

`-SelfTest` runs every read-only tool on that machine and prints a pass/fail
line each. Run it first: it is the difference between "it should work" and "it
works here".

### As an MCP client entry

```json
{
  "mcpServers": {
    "winbox": {
      "command": "powershell",
      "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\tools\\winbox-mcp.ps1"]
    }
  }
}
```

`pwsh` works the same way if PowerShell 7 is installed; the server runs on 5.1
by design, so that a fresh server needs no prerequisites.

### Over termcp, against a remote host

[termcp](https://github.com/open-mcp-ai/termcp) runs an MCP server on a host it
reaches by SSH, as a capability-trimmed extension:

```
create ext winbox --kind mcp --target <ssh-profile> --command powershell \
  --args -NoProfile -ExecutionPolicy Bypass -File winbox-mcp.ps1
```

Nothing is installed on the target and no binary has to be transferred: the
script is pushed as a file and run. This is the shape the server was built for.

## Tools

Read-only, always available:

| tool | answers |
| --- | --- |
| `host_info` | what machine is this: edition, build, model, domain, uptime, license, elevation |
| `resources` | CPU load, memory and commit, page file, the five largest processes |
| `volumes` | per-volume size/free/percent, plus physical disks with media type and health |
| `processes` | what is running, as whom, since when, with what command line (`top`, `sort`, `filter`) |
| `services` | state, start mode, logon account, binary path — and which auto-start services are NOT running |
| `listening_ports` | every TCP/UDP listener with its owning process, whether it is bound to all interfaces, and the firewall profiles' inbound defaults |
| `event_log` | recent events from System/Application/Security as structured records — where a Windows failure is actually written down |
| `scheduled_tasks` | state, next run, and the last run's result in words; task failures are invisible to every service check |
| `updates` | installed hotfixes and whether a reboot is pending, with the reason |
| `security_posture` | Defender, firewall, RDP/NLA, UAC, SMBv1, Secure Boot, TPM, BitLocker, local admins — one call |

Mutating, only with `-AllowWrite`:

| tool | answers |
| --- | --- |
| `service_control` | start/stop/restart one service, reporting the state change; refuses a deny-list that would cut management access |
| `kill_process` | terminate a pid, refusing unless the name at that pid matches the one you passed |

## Safety

A tool that can stop services on a server is a tool that can take the server
away from you. The defaults say so:

- **Read-only unless asked.** The mutating tools are absent from `tools/list`
  unless the server is started with `-AllowWrite`. A client cannot call what it
  was never offered.
- **Protected services.** `service_control` refuses WinRM, SSH, RDP, RPC, the
  event log, the task scheduler, WMI and friends — the services whose loss takes
  the session, or the host's management plane, with it.
- **Two keys to kill.** `kill_process` requires the pid *and* the name you expect
  there, because pids are reused.
- **Bounded answers.** Lists are capped and long strings trimmed, so one call
  cannot flood a context window.
- **Isolated calls.** Every tool runs in a child process of the same script with
  a timeout (`-TimeoutSeconds`, default 30). A tool that hangs, throws, or writes
  to the console cannot corrupt the protocol stream or wedge the session.

## Design notes

**Why PowerShell and not a compiled binary.** The data lives behind CIM, the
Storage module and the registry; collecting it is PowerShell either way. A
compiled wrapper would add a build per platform, a 12 MB transfer, and a second
language at the seam — in exchange for nothing the host does not already have.
One file that runs anywhere Windows runs is the smaller, more auditable artifact,
and an administrator can read it before trusting it on a server.

**Why both a summary and structuredContent.** A model wants the fields; a human
skimming a transcript wants the sentence. Returning only JSON makes transcripts
unreadable, and returning only text makes the model parse prose.

**Why each tool is one process.** Not for speed — for failure. The protocol
stream is written by exactly one function, so nothing a tool does can appear in
the middle of a frame.

**Adding a tool** is three edits in one file: write a `Get-WbX` function that
returns `@{ Summary = ...; Data = ... }`, add a registry entry with its JSON
schema, and run `-SelfTest`.

## Requirements

Windows PowerShell 5.1 or PowerShell 7+. The protocol layer is portable, so
`-ListTools` and the test suite also run on Linux and macOS under `pwsh`; the
tools themselves need Windows.

## Tests

```powershell
pwsh -NoProfile -File tests/smoke.ps1
```

Drives the server over stdio the way a client does and asserts the protocol
contract: the handshake, the catalogue, hidden write tools, unknown tools,
unknown methods, and malformed input. No Pester, no network, no Windows needed —
so it runs in CI on all three platforms.

## Roadmap

- `software` — installed programs with versions and install dates
- `disk_usage` — the largest directories under a path
- `certificates` — local machine certs and expiry, which fail silently
- `drivers` — signed/unsigned, and devices in an error state

## License

MIT — see [LICENSE](LICENSE).
