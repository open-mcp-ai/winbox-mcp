# Running winbox-mcp on a real host: field notes

Notes from the first deployment — a Tencent Cloud CVM running Windows Server 2025
Datacenter, 1 vCPU / 2 GB RAM / 50 GB, in Shanghai. They are kept because each
one cost a round trip to learn.

## The host as found

| | |
| --- | --- |
| OS | Windows Server 2025 Datacenter 10.0.26100, licensed |
| CPU / RAM | AMD EPYC 7K83, 1 core / 2 threads; 2 GB |
| Disk | C: 50 GB (33 GB free); 380 MB/s write, 330 MB/s read |
| Network | 10 Gbps NIC; 83 MB/s from the Tencent mirror, ~490 KB/s outbound to the public internet |
| Login | `termcp-relay` on port 22 — **not** Windows OpenSSH (`sshd` service is Stopped) |

`-SelfTest` passed 10/10 on this host, and the MCP surface over stdio works
through termcp's extension mechanism.

## Two things this host taught the code

**PowerShell 5.1 reads a BOM-less file as the ANSI code page.** One em dash in
the source arrived as `鈥?` in a tool description on a Chinese-locale host. The
script is now pure ASCII and CI enforces it; the alternative is a failure that
only appears on non-English machines.

**`LastTaskResult` is an unsigned HRESULT that does not fit an `Int32`.** A real
scheduled task reported `2147946720` (`0x80070420`, "could not start"), and
`[int]` on that value throws — so a status lookup became a tool failure. It is
read as `uint32` and rendered as a named verdict.

## Installing tools on a server, safely

Chocolatey was installed by downloading `install.ps1`, recording its size and
SHA256, reading its header, and only then running it — not by piping a URL into
`iex`. The first install was cut off mid-way when the SSH session dropped (see
below); the retry ran **detached**, which is the right shape for anything that
takes minutes:

```powershell
Start-Process -FilePath 'C:\ProgramData\chocolatey\bin\choco.exe' `
  -ArgumentList 'install','-y','gh','nodejs-lts','--no-progress','--limit-output' `
  -RedirectStandardOutput C:\tc\choco.out -RedirectStandardError C:\tc\choco.err `
  -WindowStyle Hidden
```

Read progress from the redirect file with SFTP (`read <session> file …`), not
from a pty: a pty reply is a time-windowed sample, and `--limit-output` prints
nothing while it downloads.

Installed this way: git 2.56.0, gh 2.103.2, node v24.22.1, npm 11.19.1,
Chocolatey 2.7.4.

## Two operational traps worth knowing

**A service inherits its environment once, at boot.** After installing tools they
were absent from a shell spawned by `termcp-relay`: machine PATH was correct, the
running process was not. Fixed in the relay rather than worked around here, and
fixed generally: `internal/sshserver/env_windows.go` now composes each session's
whole environment block the way Windows composes one for a logon — machine
entries over the inherited block, then the user's, `REG_EXPAND_SZ` expanded.

PATH was the visible half. The quiet half is `PSModulePath` and every product
home an installer writes: same bug, symptom is a module that will not load while
its directory is plainly there.

The fix is checkable without restarting anything, which is how it was checked.
Add a machine variable, then open two shells — one before the change, one after:

| | machine env has it | that shell's environment has it |
| --- | --- | --- |
| shell opened before the change | yes | no |
| shell opened after the change | yes | **yes** |
| shell opened after it was deleted | no | **no** |

The relay's process start time is unchanged across all three rows, so the later
shells read the registry rather than inheriting a snapshot. The third row is the
one that distinguishes rebuilding the block from patching one variable into it.

**This host's firewall is off on all three profiles** (`Domain`, `Private`,
`Public` all `enabled=false`, inbound default `NotConfigured`) while RDP, WinRM,
SMB and the relay's own SSH are listening on all interfaces. `security_posture`
reports exactly that, which is why the tool exists: the exposure is not visible
from any single service check.

## Sessions dropped three times, cause still open

Three interruptions, none of them a reboot (`LastBootUpTime` unchanged at 13:38
throughout). Two happened while a Chocolatey install was running — one of them
with the install already detached, so a foreground process holding the pty does
not explain it — and the third while nothing was happening on the host at all.

The relay's log shows authentication and port-forward lines with **no session-end
record**, so the connection layer was cut, not the server:

```
15:11:39  password auth user=Administrator ok=true
15:11:45  password auth user=Administrator ok=true
15:30:20  password auth user=Administrator ok=true
15:30:55  password auth user=Administrator ok=true
```

What has been ruled out, and how:

| hypothesis | test | result |
| --- | --- | --- |
| the relay restarted | process start time, log's "starting" lines | unchanged — ruled out |
| the relay crashed | service state, log | Running throughout — ruled out |
| out of memory | System event 2004 in the window | absent — ruled out |
| the daemon exits when idle | 30 s idle timeout in `internal/daemon/idle.go`; two deliberate silences of 50 s and 100 s, sessions still running afterwards | ruled out at these durations |
| TCP keepalive gives up on a silent link | client sets idle 30 s, interval 15 s, count 4 — about 90 s of unanswered probes | 100 s of silence did not kill the session — ruled out |

What is left is that something outside both processes ends the connection. The
practical answer is the same either way, and it is the shape unattended work
should take regardless: **detach anything longer than a minute** and poll a
redirect file, so a lost session costs a reconnect rather than the job.
