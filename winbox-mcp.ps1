<#
.SYNOPSIS
    winbox-mcp - a zero-install MCP server that turns a Windows host into
    structured answers instead of terminal text.

.DESCRIPTION
    An agent driving Windows over a shell spends its turns on PowerShell
    archaeology: writing the WMI query, surviving the quoting, and then parsing a
    formatted table back into facts. This server replaces that with one call per
    question and a stable JSON shape per answer.

    It speaks MCP over stdio, so any MCP client can run it. There is nothing to
    install on the host: Windows PowerShell 5.1 is already there, and this is a
    single file.

    SAFETY. Read-only by default. The two mutating tools are absent from the
    catalogue unless the server is started with -AllowWrite, and service_control
    refuses a deny-list of services whose loss would take management access with
    it.

    BOUNDED. Every list is capped and every long string is trimmed, so one call
    cannot flood a context window. Callers that want more ask for more.

.PARAMETER AllowWrite
    Publish the mutating tools (service_control, kill_process).

.PARAMETER TimeoutSeconds
    Per-tool timeout. A tool that hangs is killed and reported as an error rather
    than blocking the session.

.PARAMETER ListTools
    Print the tool catalogue as JSON and exit.

.PARAMETER SelfTest
    Run every read-only tool on this machine and report what worked. The first
    thing to run after copying this file to a new host.

.PARAMETER RunTool
    Run one tool and print its JSON result. Used internally (in a child process,
    for isolation and timeouts) and useful from the command line.

.PARAMETER ArgsJson
    JSON arguments for -RunTool.

.EXAMPLE
    # as an MCP server (what a client does)
    pwsh -NoProfile -File winbox-mcp.ps1

.EXAMPLE
    # check it works on this host
    pwsh -NoProfile -File winbox-mcp.ps1 -SelfTest

.EXAMPLE
    # use it as a plain CLI
    pwsh -NoProfile -File winbox-mcp.ps1 -RunTool volumes

    # arguments: Windows PowerShell 5.1 mangles the quotes of a JSON command-line
    # argument, so the quoting-free form is an environment variable
    $env:WINBOX_ARGS = '{"top":5,"sort":"cpu"}'
    pwsh -NoProfile -File winbox-mcp.ps1 -RunTool processes
#>
[CmdletBinding()]
param(
    [switch]$AllowWrite,
    [int]$TimeoutSeconds = 30,
    [switch]$ListTools,
    [switch]$SelfTest,
    [string]$RunTool,
    [string]$ArgsJson = '{}',
    # Set by this script when it spawns itself; reads the request from the
    # environment so no argument ever has to survive command-line quoting.
    [switch]$RunFromEnv
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:ServerName       = 'winbox-mcp'
$script:ServerVersion    = '0.1.0'
$script:DefaultProtocol  = '2024-11-05'
$script:MaxListItems     = 200

#region ---------------------------------------------------------------- plumbing

# MCP frames are one JSON object per line. Output goes through here and nowhere
# else: a stray Write-Host anywhere in a tool would otherwise land in the middle
# of the protocol stream and break the session.
function Write-Frame {
    param([Parameter(Mandatory)]$Message)
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $Message -Depth 12 -Compress))
    [Console]::Out.Flush()
}

function New-TextResult {
    param([string]$Text, $Data, [bool]$IsError = $false)
    $result = @{
        content = @(@{ type = 'text'; text = $Text })
        isError = $IsError
    }
    if ($null -ne $Data) { $result.structuredContent = $Data }
    return $result
}

function New-ToolError {
    param([string]$Text)
    return @{ content = @(@{ type = 'text'; text = $Text }); isError = $true }
}

#endregion

#region ------------------------------------------------------------- tool registry

# The catalogue is data, so a client's tools/list and the dispatcher can never
# disagree about what exists.
function Get-WbToolRegistry {
    param([switch]$IncludeWrite)

    $tools = @(
        @{
            name        = 'host_info'
            description = 'Identify the Windows host: edition and build, architecture, machine model, domain, boot time and uptime, time zone, license state, and whether this process is elevated. Start here when you do not know what machine you are on.'
            schema      = @{ type = 'object'; properties = @{}; additionalProperties = $false }
            handler     = 'Get-WbHostInfo'
            write       = $false
        },
        @{
            name        = 'resources'
            description = 'CPU load, memory and commit charge, page file, and the five largest processes. One call answers "is this host under pressure right now".'
            schema      = @{ type = 'object'; properties = @{}; additionalProperties = $false }
            handler     = 'Get-WbResources'
            write       = $false
        },
        @{
            name        = 'volumes'
            description = 'Every volume with size, free space and free percentage, plus the physical disks behind them with media type (SSD/HDD) and health. Answers "is the disk filling up" and "is a disk failing".'
            schema      = @{ type = 'object'; properties = @{}; additionalProperties = $false }
            handler     = 'Get-WbVolumes'
            write       = $false
        },
        @{
            name        = 'processes'
            description = 'Running processes with owner, parent, working set, CPU time and command line, filterable by name and sorted by memory or CPU. Use it to find what a service actually runs as, or which process is consuming the host.'
            schema      = @{
                type       = 'object'
                properties = @{
                    top    = @{ type = 'integer'; description = 'how many processes to return, 1-200 (default 20)'; minimum = 1; maximum = 200 }
                    sort   = @{ type = 'string'; description = 'memory (default), cpu, or name'; enum = @('memory', 'cpu', 'name') }
                    filter = @{ type = 'string'; description = 'regular expression matched against the process name, e.g. "sql|postgres"' }
                }
                additionalProperties = $false
            }
            handler     = 'Get-WbProcesses'
            write       = $false
        },
        @{
            name        = 'services'
            description = 'Windows services with state, start mode, logon account and binary path, plus the list of services set to auto-start that are NOT running - usually the reason a host is broken. Read-only: use service_control to change one.'
            schema      = @{
                type       = 'object'
                properties = @{
                    filter = @{ type = 'string'; description = 'regular expression matched against the service name or display name' }
                    state  = @{ type = 'string'; description = 'running or stopped'; enum = @('running', 'stopped') }
                }
                additionalProperties = $false
            }
            handler     = 'Get-WbServices'
            write       = $false
        },
        @{
            name        = 'listening_ports'
            description = 'TCP and UDP endpoints this host listens on, with the owning process and whether the socket is bound to all interfaces, plus the firewall profiles inbound defaults. Answers "what is exposed here and what owns that port" without a netstat-and-grep round trip.'
            schema      = @{
                type       = 'object'
                properties = @{
                    port = @{ type = 'integer'; description = 'only report this local port' }
                }
                additionalProperties = $false
            }
            handler     = 'Get-WbPorts'
            write       = $false
        },
        @{
            name        = 'event_log'
            description = 'Recent events from a Windows event log, as structured records: time, id, level, provider and message. Defaults to errors from the System log in the last day. This is where the reason a Windows host is misbehaving is actually written down - check it before guessing.'
            schema      = @{
                type       = 'object'
                properties = @{
                    log     = @{ type = 'string'; description = 'log name: System (default), Application, Security, or any other' }
                    level   = @{ type = 'string'; description = 'error (default), warning, information, or all'; enum = @('error', 'warning', 'information', 'all') }
                    count   = @{ type = 'integer'; description = 'how many events, 1-200 (default 20)'; minimum = 1; maximum = 200 }
                    minutes = @{ type = 'integer'; description = 'how far back to look, in minutes (default 1440)' }
                }
                additionalProperties = $false
            }
            handler     = 'Get-WbEventLog'
            write       = $false
        },
        @{
            name        = 'scheduled_tasks'
            description = 'Scheduled tasks with state, next run, and the result of the last run in words (success, running, not yet run). Task failures are a common reason a Windows server stops doing its job while every service still looks healthy. The hundreds of Microsoft maintenance tasks are excluded unless asked for.'
            schema      = @{
                type       = 'object'
                properties = @{
                    filter            = @{ type = 'string'; description = 'regular expression matched against the task name or folder' }
                    state             = @{ type = 'string'; description = 'ready, running or disabled'; enum = @('ready', 'running', 'disabled') }
                    include_microsoft = @{ type = 'boolean'; description = 'also list the built-in \\Microsoft\\ maintenance tasks (default false)' }
                }
                additionalProperties = $false
            }
            handler     = 'Get-WbScheduledTasks'
            write       = $false
        },
        @{
            name        = 'updates'
            description = 'Installed hotfixes and whether a reboot is pending, with the reason it is pending (servicing, Windows Update, or files waiting to be renamed). A pending reboot is invisible to every other check and explains a surprising number of \"the fix is not in effect\" reports.'
            schema      = @{ type = 'object'; properties = @{}; additionalProperties = $false }
            handler     = 'Get-WbUpdates'
            write       = $false
        },
        @{
            name        = 'security_posture'
            description = 'The exposure of this host in one call: Defender state and recent detections, firewall profiles and their inbound defaults, RDP and NLA, UAC, SMBv1, Secure Boot, TPM, BitLocker volumes, and who is a local administrator. Use it to answer \"is this server exposed\" without five separate queries.'
            schema      = @{ type = 'object'; properties = @{}; additionalProperties = $false }
            handler     = 'Get-WbSecurityPosture'
            write       = $false
        },
        @{
            name        = 'service_control'
            description = 'Start, stop or restart one Windows service and report the state change. Refuses a deny-list of services that would cut management access off (WinRM, SSH, RPC, the event log, the scheduler).'
            schema      = @{
                type       = 'object'
                properties = @{
                    name   = @{ type = 'string'; description = 'exact service name as reported by the services tool (not the display name)' }
                    action = @{ type = 'string'; description = 'start, stop or restart'; enum = @('start', 'stop', 'restart') }
                }
                required             = @('name', 'action')
                additionalProperties = $false
            }
            handler     = 'Invoke-WbServiceControl'
            write       = $true
        },
        @{
            name        = 'kill_process'
            description = 'Terminate one process by pid, refusing unless the name at that pid matches the one you passed. Pids are reused, so the name is the guard.'
            schema      = @{
                type       = 'object'
                properties = @{
                    pid  = @{ type = 'integer'; description = 'process id' }
                    name = @{ type = 'string'; description = 'the process name expected at that pid; the kill is refused if it does not match' }
                }
                required             = @('pid', 'name')
                additionalProperties = $false
            }
            handler     = 'Invoke-WbKillProcess'
            write       = $true
        }
    )

    if (-not $IncludeWrite) { $tools = @($tools | Where-Object { -not $_.write }) }
    return $tools
}

function Find-WbTool {
    param([string]$Name, [switch]$IncludeWrite)
    return Get-WbToolRegistry -IncludeWrite:$IncludeWrite |
        Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

#endregion

#region ------------------------------------------------------------------- tools

function Get-WbHostInfo {
    param($ToolArgs)

    $os   = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $cv   = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $build = [string]$cv.CurrentBuild
    if ($null -ne $cv.UBR) { $build = $build + '.' + [string]$cv.UBR }

    # LicenseStatus is an enum whose numbers mean nothing to a reader, so it is
    # translated here instead of in every caller.
    $license = 'unknown'
    try {
        $lic = Get-CimInstance -ClassName SoftwareLicensingProduct `
            -Filter 'PartialProductKey IS NOT NULL' -ErrorAction Stop | Select-Object -First 1
        if ($lic) {
            switch ([int]$lic.LicenseStatus) {
                0 { $license = 'unlicensed' }
                1 { $license = 'licensed' }
                2 { $license = 'out-of-box grace' }
                3 { $license = 'out-of-tolerance grace' }
                4 { $license = 'non-genuine grace' }
                5 { $license = 'notification' }
                6 { $license = 'extended grace' }
                default { $license = 'status ' + [string]$lic.LicenseStatus }
            }
        }
    } catch { }

    $elevated = $false
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $elevated  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }

    $boot   = [datetime]$os.LastBootUpTime
    $uptime = [int64]((Get-Date) - $boot).TotalSeconds

    $data = [pscustomobject]@{
        hostname = $env:COMPUTERNAME
        os = [pscustomobject]@{
            caption        = ([string]$os.Caption).Trim()
            version        = [string]$os.Version
            build          = $build
            arch           = [string]$os.OSArchitecture
            install_date   = ([datetime]$os.InstallDate).ToString('o')
            time_zone      = (Get-TimeZone).Id
            license_status = $license
        }
        hardware = [pscustomobject]@{
            manufacturer = ([string]$cs.Manufacturer).Trim()
            model        = ([string]$cs.Model).Trim()
            serial       = ([string]$bios.SerialNumber).Trim()
            domain       = [string]$cs.Domain
            in_domain    = [bool]$cs.PartOfDomain
        }
        runtime = [pscustomobject]@{
            powershell      = $PSVersionTable.PSVersion.ToString()
            elevated        = $elevated
            processor_count = [int]$cs.NumberOfProcessors
        }
        boot_time      = $boot.ToString('o')
        uptime_seconds = $uptime
    }

    $up   = [TimeSpan]::FromSeconds($uptime)
    $priv = 'standard user'
    if ($elevated) { $priv = 'elevated' }
    $summary = @(
        "$($data.hostname) - $($data.os.caption) $($data.os.version) ($($data.os.arch))"
        "$($data.hardware.manufacturer) $($data.hardware.model)  -  domain $($data.hardware.domain)"
        "uptime $([int]$up.TotalHours)h $($up.Minutes)m  -  booted $($data.boot_time)  -  $($data.os.time_zone)  -  $priv  -  license $license"
    ) -join "`n"

    return @{ Summary = $summary; Data = $data }
}

function Get-WbResources {
    param($ToolArgs)

    $os  = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs  = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1

    # Win32_Processor.LoadPercentage is a snapshot that is often stale; the perf
    # counter is the one that moves. Which one answered is reported, so a caller
    # never has to guess how much to trust the number.
    $load   = $null
    $source = 'Win32_Processor.LoadPercentage'
    try {
        $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor `
            -Filter "Name='_Total'" -ErrorAction Stop
        if ($perf) {
            $load   = [int]$perf.PercentProcessorTime
            $source = 'Win32_PerfFormattedData_PerfOS_Processor'
        }
    } catch { }
    if ($null -eq $load) { $load = [int]$cpu.LoadPercentage }

    $totalMB = [int][math]::Round($os.TotalVisibleMemorySize / 1KB)
    $freeMB  = [int][math]::Round($os.FreePhysicalMemory / 1KB)
    $usedPct = 0
    if ($totalMB -gt 0) { $usedPct = [int][math]::Round(100 * ($totalMB - $freeMB) / $totalMB) }

    $top = @()
    foreach ($p in @(Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5)) {
        $top += [pscustomobject]@{
            name           = [string]$p.ProcessName
            pid            = [int]$p.Id
            working_set_mb = [math]::Round($p.WorkingSet64 / 1MB, 1)
        }
    }

    $pageFile = [pscustomobject]@{ name = ''; allocated_mb = 0; current_use_mb = 0; peak_use_mb = 0 }
    try {
        $pf = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop | Select-Object -First 1
        if ($pf) {
            $pageFile = [pscustomobject]@{
                name           = [string]$pf.Name
                allocated_mb   = [int]$pf.AllocatedBaseSize
                current_use_mb = [int]$pf.CurrentUsage
                peak_use_mb    = [int]$pf.PeakUsage
            }
        }
    } catch { }

    $data = [pscustomobject]@{
        cpu = [pscustomobject]@{
            name              = ([string]$cpu.Name).Trim()
            cores             = [int]$cpu.NumberOfCores
            threads           = [int]$cpu.NumberOfLogicalProcessors
            load_percent      = $load
            max_clock_mhz     = [int]$cpu.MaxClockSpeed
            current_clock_mhz = [int]$cpu.CurrentClockSpeed
            virtualized       = [bool]$cs.HypervisorPresent
            load_source       = $source
        }
        memory = [pscustomobject]@{
            total_mb        = $totalMB
            free_mb         = $freeMB
            used_percent    = $usedPct
            commit_total_mb = [int][math]::Round($os.TotalVirtualMemorySize / 1KB)
            commit_free_mb  = [int][math]::Round($os.FreeVirtualMemory / 1KB)
        }
        page_file     = $pageFile
        top_processes = @($top)
    }

    $lines = @(
        "cpu  $($data.cpu.name)  $($data.cpu.cores)c/$($data.cpu.threads)t  $($data.cpu.load_percent)% busy"
        "mem  $($data.memory.total_mb - $data.memory.free_mb)/$($data.memory.total_mb) MB used ($($data.memory.used_percent)%), commit free $($data.memory.commit_free_mb) MB"
    )
    if ($pageFile.name -ne '') {
        $lines += "page $($pageFile.name) $($pageFile.current_use_mb) MB used of $($pageFile.allocated_mb) MB"
    }
    foreach ($p in $top) { $lines += ("  {0,-26} {1,6}  {2,8:N1} MB" -f $p.name, $p.pid, $p.working_set_mb) }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbVolumes {
    param($ToolArgs)

    $volumes = @()
    foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
        $pct = 0
        if ($d.Size -gt 0) { $pct = [int][math]::Round(100 * $d.FreeSpace / $d.Size) }
        $volumes += [pscustomobject]@{
            letter       = [string]$d.DeviceID
            label        = [string]$d.VolumeName
            file_system  = [string]$d.FileSystem
            total_gb     = [math]::Round($d.Size / 1GB, 2)
            free_gb      = [math]::Round($d.FreeSpace / 1GB, 2)
            free_percent = $pct
        }
    }

    # Get-PhysicalDisk is the only place media type and health live; it is absent
    # on images without the Storage module, so its absence is data, not a failure.
    $physical = @()
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        try {
            foreach ($p in @(Get-PhysicalDisk -ErrorAction Stop)) {
                $physical += [pscustomobject]@{
                    name      = [string]$p.FriendlyName
                    media     = [string]$p.MediaType
                    health    = [string]$p.HealthStatus
                    size_gb   = [math]::Round($p.Size / 1GB, 1)
                    bus_type  = [string]$p.BusType
                    is_system = [bool]$p.IsSystem
                }
            }
        } catch { }
    }

    $drives = @()
    foreach ($dr in @(Get-CimInstance -ClassName Win32_DiskDrive)) {
        $size = 0
        if ($dr.Size) { $size = [math]::Round($dr.Size / 1GB, 1) }
        $drives += [pscustomobject]@{
            model     = ([string]$dr.Model).Trim()
            interface = [string]$dr.InterfaceType
            size_gb   = $size
            status    = [string]$dr.Status
        }
    }

    $data = [pscustomobject]@{ volumes = @($volumes); physical_disks = @($physical); drives = @($drives) }

    $lines = @()
    foreach ($v in $volumes) {
        $lines += ("{0} {1,-14} {2,-5} {3,7:N1} GB free of {4,7:N1} GB ({5}%)" -f `
            $v.letter, $v.label, $v.file_system, $v.free_gb, $v.total_gb, $v.free_percent)
    }
    foreach ($p in $physical) {
        $lines += ("disk {0,-30} {1,-12} {2,-10} {3,7:N1} GB" -f $p.name, $p.media, $p.health, $p.size_gb)
    }
    if ($lines.Count -eq 0) { $lines = @('no fixed volumes found') }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbProcesses {
    param($ToolArgs)

    $top = 20
    if ($ToolArgs -and $ToolArgs.top) { $top = [int]$ToolArgs.top }
    if ($top -lt 1)   { $top = 1 }
    if ($top -gt 200) { $top = 200 }

    $sort = 'memory'
    if ($ToolArgs -and $ToolArgs.sort) { $sort = ([string]$ToolArgs.sort).ToLower() }
    if (@('memory', 'cpu', 'name') -notcontains $sort) {
        throw "sort must be memory, cpu or name (got '$sort')"
    }

    $filter = ''
    if ($ToolArgs -and $ToolArgs.filter) { $filter = [string]$ToolArgs.filter }

    $all = @(Get-CimInstance -ClassName Win32_Process)
    if ($filter -ne '') { $all = @($all | Where-Object { $_.Name -match $filter }) }
    $total = $all.Count

    if ($sort -eq 'cpu') {
        $sel = @($all | Sort-Object -Property @{ Expression = { $_.UserModeTime + $_.KernelModeTime } } -Descending |
            Select-Object -First $top)
    } elseif ($sort -eq 'name') {
        $sel = @($all | Sort-Object -Property Name | Select-Object -First $top)
    } else {
        $sel = @($all | Sort-Object -Property WorkingSetSize -Descending | Select-Object -First $top)
    }

    $out = @()
    foreach ($p in $sel) {
        # GetOwner is a per-process WMI call, so it is asked only for the
        # processes being returned and never for the whole machine.
        $owner = ''
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o -and $o.User) { $owner = [string]$o.Domain + '\' + [string]$o.User }
        } catch { }

        $start = ''
        if ($p.CreationDate) { $start = ([datetime]$p.CreationDate).ToString('o') }

        $cmd = [string]$p.CommandLine
        if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) + [char]0x2026 }

        $out += [pscustomobject]@{
            pid            = [int]$p.ProcessId
            parent_pid     = [int]$p.ParentProcessId
            name           = [string]$p.Name
            owner          = $owner
            working_set_mb = [math]::Round($p.WorkingSetSize / 1MB, 1)
            cpu_seconds    = [math]::Round(($p.UserModeTime + $p.KernelModeTime) / 10000000, 1)
            threads        = [int]$p.ThreadCount
            start_time     = $start
            command_line   = $cmd
        }
    }

    $data = [pscustomobject]@{
        total_processes = $total
        sort            = $sort
        filter          = $filter
        processes       = @($out)
    }

    $lines = @("$total processes match (sorted by $sort), showing $($out.Count)")
    foreach ($p in $out) {
        $lines += ("  {0,-30} {1,6}  {2,9:N1} MB  {3,8:N1}s  {4}" -f $p.name, $p.pid, $p.working_set_mb, $p.cpu_seconds, $p.owner)
    }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbServices {
    param($ToolArgs)

    $filter = ''
    if ($ToolArgs -and $ToolArgs.filter) { $filter = [string]$ToolArgs.filter }

    $state = ''
    if ($ToolArgs -and $ToolArgs.state) { $state = ([string]$ToolArgs.state).ToLower() }
    if (@('', 'running', 'stopped') -notcontains $state) {
        throw "state must be running or stopped (got '$state')"
    }

    $all = @(Get-CimInstance -ClassName Win32_Service)
    if ($filter -ne '') {
        $all = @($all | Where-Object { ($_.Name -match $filter) -or ($_.DisplayName -match $filter) })
    }
    if ($state -eq 'running') {
        $all = @($all | Where-Object { $_.State -eq 'Running' })
    } elseif ($state -eq 'stopped') {
        $all = @($all | Where-Object { $_.State -eq 'Stopped' })
    }

    $list = @()
    foreach ($s in @($all | Sort-Object -Property Name | Select-Object -First $script:MaxListItems)) {
        $list += [pscustomobject]@{
            name         = [string]$s.Name
            display_name = [string]$s.DisplayName
            state        = [string]$s.State
            start_mode   = [string]$s.StartMode
            start_name   = [string]$s.StartName
            exit_code    = [int]$s.ExitCode
            pid          = [int]$s.ProcessId
            path         = [string]$s.PathName
        }
    }

    $broken = @()
    foreach ($s in @($all | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | Select-Object -First 50)) {
        $broken += [string]$s.Name
    }

    $data = [pscustomobject]@{
        matched                = $all.Count
        services               = @($list)
        auto_start_but_stopped = @($broken)
    }

    $lines = @("$($all.Count) services match, showing $($list.Count)")
    if ($broken.Count -gt 0) { $lines += "auto-start but NOT running: $($broken -join ', ')" }
    foreach ($s in $list) {
        $lines += ("  {0,-34} {1,-8} {2,-9} {3}" -f $s.name, $s.state, $s.start_mode, $s.display_name)
    }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbPorts {
    param($ToolArgs)

    $onlyPort = 0
    if ($ToolArgs -and $ToolArgs.port) { $onlyPort = [int]$ToolArgs.port }

    # One row per (protocol, port), collecting every address it is bound to: a
    # port bound to 127.0.0.1 and to 0.0.0.0 at once is one row, and the row says
    # all_interfaces, so the difference is not lost.
    $entries = @{}

    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $key = 'tcp/' + [string]$c.LocalPort
        if (-not $entries.ContainsKey($key)) {
            $entries[$key] = [pscustomobject]@{
                port       = [int]$c.LocalPort
                protocol   = 'tcp'
                addresses  = @()
                process_id = [int]$c.OwningProcess
            }
        }
        $entries[$key].addresses += [string]$c.LocalAddress
    }

    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $key = 'udp/' + [string]$u.LocalPort
        if (-not $entries.ContainsKey($key)) {
            $entries[$key] = [pscustomobject]@{
                port       = [int]$u.LocalPort
                protocol   = 'udp'
                addresses  = @()
                process_id = [int]$u.OwningProcess
            }
        }
        $entries[$key].addresses += [string]$u.LocalAddress
    }

    $list = @()
    foreach ($key in @($entries.Keys | Sort-Object -Property { $entries[$_].port })) {
        $e = $entries[$key]
        if ($onlyPort -gt 0 -and $e.port -ne $onlyPort) { continue }

        $name = ''
        $path = ''
        if ($e.process_id -gt 0) {
            try {
                $pr   = Get-Process -Id $e.process_id -ErrorAction Stop
                $name = [string]$pr.ProcessName
                $path = [string]$pr.Path
            } catch { }
        }

        $addrs = @($e.addresses | Sort-Object -Unique)
        $allIf = $false
        foreach ($a in $addrs) {
            if ($a -eq '0.0.0.0' -or $a -eq '::' -or $a -eq '*') { $allIf = $true }
        }

        $list += [pscustomobject]@{
            port           = [int]$e.port
            protocol       = [string]$e.protocol
            addresses      = $addrs
            all_interfaces = $allIf
            pid            = [int]$e.process_id
            process        = $name
            process_path   = $path
        }
    }

    # Binding to all interfaces is not the same as being reachable: the firewall
    # profile's inbound default decides. Both facts are reported, neither guessed.
    $fw = @()
    foreach ($f in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $fw += [pscustomobject]@{
            profile         = [string]$f.Name
            enabled         = [bool]$f.Enabled
            default_inbound = [string]$f.DefaultInboundAction
        }
    }

    $data = [pscustomobject]@{ listening = @($list); firewall = @($fw) }

    $lines = @("$($list.Count) listening endpoints")
    foreach ($l in $list) {
        $scope = 'local'
        if ($l.all_interfaces) { $scope = 'all-interfaces' }
        $lines += ("  {0,5}/{1,-3} {2,-16} {3,-18} {4}" -f $l.port, $l.protocol, $scope, $l.process, ($l.addresses -join ','))
    }
    foreach ($f in $fw) {
        $lines += ("firewall {0,-8} enabled={1} default-inbound={2}" -f $f.profile, $f.enabled, $f.default_inbound)
    }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Invoke-WbServiceControl {
    param($ToolArgs)

    $name   = [string]$ToolArgs.name
    $action = ([string]$ToolArgs.action).ToLower()

    if ($name.Trim() -eq '') { throw 'name is required' }
    if (@('start', 'stop', 'restart') -notcontains $action) {
        throw "action must be start, stop or restart (got '$action')"
    }

    # A deny-list, not an allow-list: the point is to refuse the handful of
    # services whose loss takes management access (or the host) with it. Anything
    # else is the caller's business, and refusing it would make the tool useless.
    $protected = @(
        'winrm', 'ssh', 'sshd', 'termservice', 'rpcs', 'dcomlaunch', 'plugplay', 'power',
        'lsm', 'samss', 'eventlog', 'schedule', 'winmgmt', 'profsvc', 'cryptsvc', 'trustedinstaller'
    )

    $before = ''
    $after  = ''
    $ok     = $false
    $msg    = ''

    if ($protected -contains $name.ToLower()) {
        $msg = "$name is on the protected list: stopping it would break management access or the host"
    } else {
        try {
            $svc    = Get-Service -Name $name -ErrorAction Stop
            $before = [string]$svc.Status

            switch ($action) {
                'start' {
                    if ($svc.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop; $msg = 'started' }
                    else { $msg = 'already running' }
                }
                'stop' {
                    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction Stop; $msg = 'stopped' }
                    else { $msg = 'already stopped' }
                }
                'restart' {
                    Restart-Service -Name $name -Force -ErrorAction Stop
                    $msg = 'restarted'
                }
            }
            $ok = $true
        } catch {
            $msg = $_.Exception.Message
        }
        try {
            $check = Get-Service -Name $name -ErrorAction Stop
            $after = [string]$check.Status
        } catch { }
    }

    $data = [pscustomobject]@{
        name         = $name
        action       = $action
        state_before = $before
        state_after  = $after
        ok           = $ok
        message      = $msg
    }

    return @{ Summary = "$action $name : $before -> $after (ok=$ok) $msg"; Data = $data }
}

function Invoke-WbKillProcess {
    param($ToolArgs)

    $targetPid = [int]$ToolArgs.pid
    $want      = [string]$ToolArgs.name

    if ($targetPid -le 0) { throw 'pid must be positive' }
    if ($want.Trim() -eq '') { throw 'name is required: it is the guard against killing the wrong process' }

    $existed = $false
    $actual  = ''
    $ok      = $false
    $msg     = ''

    try {
        $proc    = Get-Process -Id $targetPid -ErrorAction Stop
        $existed = $true
        $actual  = [string]$proc.ProcessName

        # Pids are reused, so the caller's belief is checked rather than trusted:
        # killing pid 1234 because it was 'tomcat' a minute ago is how the wrong
        # service dies.
        if ($actual -ne $want -and ($actual + '.exe') -ne $want) {
            $msg = "refused: pid $targetPid is running $actual, not $want"
        } else {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            $ok  = $true
            $msg = 'terminated'
        }
    } catch {
        $msg = $_.Exception.Message
    }

    $data = [pscustomobject]@{ pid = $targetPid; name = $actual; existed = $existed; ok = $ok; message = $msg }
    return @{ Summary = "kill $targetPid ($actual): ok=$ok $msg"; Data = $data }
}

function Get-WbEventLog {
    param($ToolArgs)

    $log = 'System'
    if ($ToolArgs -and $ToolArgs.log) { $log = [string]$ToolArgs.log }

    $level = 'error'
    if ($ToolArgs -and $ToolArgs.level) { $level = ([string]$ToolArgs.level).ToLower() }
    if (@('error', 'warning', 'information', 'all') -notcontains $level) {
        throw "level must be error, warning, information or all (got '$level')"
    }

    $count = 20
    if ($ToolArgs -and $ToolArgs.count) { $count = [int]$ToolArgs.count }
    if ($count -lt 1)   { $count = 1 }
    if ($count -gt 200) { $count = 200 }

    $minutes = 1440
    if ($ToolArgs -and $ToolArgs.minutes) { $minutes = [int]$ToolArgs.minutes }
    if ($minutes -lt 1) { $minutes = 1 }

    # Get-WinEvent wants the numeric levels, not their names.
    $levels = @(2, 3, 4)
    if ($level -eq 'error')       { $levels = @(2) }
    if ($level -eq 'warning')     { $levels = @(3) }
    if ($level -eq 'information') { $levels = @(4) }

    $since  = (Get-Date).AddMinutes(-$minutes)
    $filter = @{ LogName = $log; Level = $levels; StartTime = $since }

    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $count -ErrorAction Stop)
    } catch {
        # An empty result set is an answer, not a failure. Anything else (access
        # denied on the Security log, an unknown log name) is a real error and is
        # reported as one.
        if ($_.Exception.Message -notmatch 'No events were found') { throw }
    }

    $out = @()
    foreach ($e in $events) {
        $msg = ''
        try { $msg = [string]$e.Message } catch { }
        $msg = ($msg -replace "`r?`n", ' ').Trim()
        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }

        $when = ''
        $short = ''
        if ($e.TimeCreated) {
            $when  = ([datetime]$e.TimeCreated).ToString('o')
            $short = ([datetime]$e.TimeCreated).ToString('MM-dd HH:mm:ss')
        }

        $out += [pscustomobject]@{
            time_created = $when
            time_short   = $short
            id           = [int]$e.Id
            level        = [string]$e.LevelDisplayName
            provider     = [string]$e.ProviderName
            message      = $msg
        }
    }

    $data = [pscustomobject]@{
        log            = $log
        level          = $level
        window_minutes = $minutes
        events         = @($out)
    }

    $lines = @("$($out.Count) events from $log (level $level, last $minutes min)")
    foreach ($e in $out) {
        $short = $e.message
        if ($short.Length -gt 110) { $short = $short.Substring(0, 110) + '...' }
        $lines += ("  {0}  {1,-12} {2,6}  {3,-26} {4}" -f $e.time_short, $e.level, $e.id, $e.provider, $short)
    }
    if ($out.Count -eq 0) { $lines += '  (nothing in that window)' }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function ConvertFrom-WbTaskResult {
    param($Code)

    # The codes are HRESULT-shaped and mean nothing to a reader; the ones a server
    # actually produces are named here.
    #
    # The value is UNSIGNED and does not fit an Int32: a real host reports
    # 2147946720 (0x80070420) for a task that could not start. Casting that to
    # [int] throws, which is how a status lookup turned into a tool failure.
    $raw = [uint32]$Code
    switch ($raw) {
        0          { return 'success' }
        267009     { return 'running' }
        267011     { return 'not yet run' }
        267014     { return 'terminated by user' }
        267010     { return 'disabled' }
        267012     { return 'no more runs' }
        2147942402 { return 'not found (0x80070002)' }
        2147943712 { return 'could not start (0x80070420)' }
        2147943785 { return 'access denied (0x80070569)' }
        default    { return ('result 0x{0:X8}' -f $raw) }
    }
}

function Get-WbScheduledTasks {
    param($ToolArgs)

    $filter = ''
    if ($ToolArgs -and $ToolArgs.filter) { $filter = [string]$ToolArgs.filter }

    $state = ''
    if ($ToolArgs -and $ToolArgs.state) { $state = ([string]$ToolArgs.state).ToLower() }
    if (@('', 'ready', 'running', 'disabled') -notcontains $state) {
        throw "state must be ready, running or disabled (got '$state')"
    }

    $includeMicrosoft = $false
    if ($ToolArgs -and $null -ne $ToolArgs.include_microsoft) {
        $includeMicrosoft = [bool]$ToolArgs.include_microsoft
    }

    $all = @(Get-ScheduledTask -ErrorAction Stop)
    # The hundreds of \Microsoft\ maintenance tasks are noise in every question a
    # person actually asks; they are opt-in rather than opt-out.
    if (-not $includeMicrosoft) {
        $all = @($all | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    }
    if ($filter -ne '') {
        $all = @($all | Where-Object { ($_.TaskName -match $filter) -or ($_.TaskPath -match $filter) })
    }
    if ($state -ne '') {
        $all = @($all | Where-Object { ([string]$_.State).ToLower() -eq $state })
    }

    $total = $all.Count
    $sel   = @($all | Sort-Object -Property TaskPath, TaskName | Select-Object -First 100)

    $out = @()
    foreach ($t in $sel) {
        # Get-ScheduledTaskInfo is one CIM call per task, so it is asked only for
        # the tasks being returned.
        $info = $null
        try {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
        } catch { }

        $action = ''
        if ($t.Actions -and @($t.Actions).Count -gt 0) {
            $a = @($t.Actions)[0]
            $action = ([string]$a.Execute).Trim()
            if ($a.Arguments) { $action = $action + ' ' + [string]$a.Arguments }
            if ($action.Length -gt 200) { $action = $action.Substring(0, 200) + '...' }
        }

        $last    = ''
        $next    = ''
        $result  = $null
        $verdict = ''
        if ($info) {
            if ($info.LastRunTime -and ([datetime]$info.LastRunTime).Year -gt 1900) {
                $last = ([datetime]$info.LastRunTime).ToString('o')
            }
            if ($info.NextRunTime -and ([datetime]$info.NextRunTime).Year -gt 1900) {
                $next = ([datetime]$info.NextRunTime).ToString('o')
            }
            $result  = [long]$info.LastTaskResult
            $verdict = ConvertFrom-WbTaskResult $result
        }

        $out += [pscustomobject]@{
            name         = [string]$t.TaskName
            path         = [string]$t.TaskPath
            state        = [string]$t.State
            run_as       = [string]$t.Principal.UserId
            last_run     = $last
            last_result  = $result
            last_verdict = $verdict
            next_run     = $next
            action       = $action
        }
    }

    $data = [pscustomobject]@{
        matched            = $total
        include_microsoft  = $includeMicrosoft
        tasks              = @($out)
    }

    $lines = @("$total tasks match, showing $($out.Count)")
    foreach ($t in $out) {
        $lines += ("  {0,-34} {1,-9} {2,-16} {3}" -f ($t.path + $t.name), $t.state, $t.last_verdict, $t.next_run)
    }
    if ($out.Count -eq 0) { $lines += '  (nothing matches)' }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbUpdates {
    param($ToolArgs)

    $hotfixes = @()
    foreach ($h in @(Get-HotFix -ErrorAction SilentlyContinue |
            Sort-Object -Property InstalledOn -Descending | Select-Object -First 50)) {
        $when = ''
        if ($h.InstalledOn) { $when = ([datetime]$h.InstalledOn).ToString('o') }
        $hotfixes += [pscustomobject]@{
            id           = [string]$h.HotFixID
            description  = [string]$h.Description
            installed_on = $when
        }
    }

    # A pending reboot is a set of registry facts rather than one flag, and which
    # one is set says what is waiting to be applied.
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'component based servicing'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'windows update'
    }
    $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pfro -and $pfro.PendingFileRenameOperations) {
        $reasons += 'pending file rename operations'
    }

    $lastSearch  = ''
    $lastInstall = ''
    try {
        $d = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -ErrorAction Stop
        if ($d.LastSuccessTime) { $lastSearch = [string]$d.LastSuccessTime }
    } catch { }
    try {
        $i = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -ErrorAction Stop
        if ($i.LastSuccessTime) { $lastInstall = [string]$i.LastSuccessTime }
    } catch { }

    $data = [pscustomobject]@{
        hotfixes        = @($hotfixes)
        pending_reboot  = ($reasons.Count -gt 0)
        pending_reasons = @($reasons)
        last_search     = $lastSearch
        last_install    = $lastInstall
    }

    $lines = @("$($hotfixes.Count) hotfixes recorded")
    if ($reasons.Count -gt 0) {
        $lines += 'PENDING REBOOT: ' + ($reasons -join ', ')
    } else {
        $lines += 'no reboot pending'
    }
    if ($lastInstall -ne '') { $lines += "last update install: $lastInstall" }
    foreach ($h in @($hotfixes | Select-Object -First 8)) {
        $lines += ("  {0,-12} {1,-24} {2}" -f $h.id, $h.description, $h.installed_on)
    }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

function Get-WbSecurityPosture {
    param($ToolArgs)

    # Every block below is independently optional: a Server Core image has no
    # Defender cmdlets, a VM has no TPM, and a host without BitLocker has no
    # volumes to report. Missing is reported as missing, never as false.
    $defender = [pscustomobject]@{
        available = $false; am_service = $null; real_time = $null; signature_age_days = $null
        signature_updated = ''; tamper_protected = $null; last_quick_scan = ''; threats = @()
    }
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop

            $threats = @()
            try {
                foreach ($t in @(Get-MpThreatDetection -ErrorAction Stop |
                        Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 5)) {
                    $detected = ''
                    if ($t.InitialDetectionTime) { $detected = ([datetime]$t.InitialDetectionTime).ToString('o') }
                    $threats += [pscustomobject]@{
                        detected = $detected
                        threat   = [string]$t.ThreatID
                        cleaned  = [bool]$t.CleaningActionSuccess
                    }
                }
            } catch { }

            $sigUpdated = ''
            if ($mp.AntivirusSignatureLastUpdated) { $sigUpdated = ([datetime]$mp.AntivirusSignatureLastUpdated).ToString('o') }
            $quickScan = ''
            if ($mp.QuickScanEndTime) { $quickScan = ([datetime]$mp.QuickScanEndTime).ToString('o') }

            $defender = [pscustomobject]@{
                available          = $true
                am_service         = [bool]$mp.AMServiceEnabled
                real_time          = [bool]$mp.RealTimeProtectionEnabled
                signature_age_days = [int]$mp.AntivirusSignatureAge
                signature_updated  = $sigUpdated
                tamper_protected   = [bool]$mp.IsTamperProtected
                last_quick_scan    = $quickScan
                threats            = @($threats)
            }
        } catch { }
    }

    $firewall = @()
    foreach ($f in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $firewall += [pscustomobject]@{
            profile         = [string]$f.Name
            enabled         = [bool]$f.Enabled
            default_inbound = [string]$f.DefaultInboundAction
        }
    }

    $rdpEnabled = $null
    $rdpNla     = $null
    try {
        $ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $rdpEnabled = ([int]$ts.fDenyTSConnections -eq 0)
    } catch { }
    try {
        $ws = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop
        $rdpNla = ([int]$ws.UserAuthentication -eq 1)
    } catch { }

    $uacEnabled = $null
    $uacPrompt  = ''
    try {
        $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        if ($null -ne $p.EnableLUA) { $uacEnabled = ([int]$p.EnableLUA -eq 1) }
        if ($null -ne $p.ConsentPromptBehaviorAdmin) { $uacPrompt = [string]$p.ConsentPromptBehaviorAdmin }
    } catch { }

    $smb1 = $null
    try { $smb1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }

    $secureBoot = $null
    try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }

    $tpmPresent = $null
    $tpmReady   = $null
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $t = Get-Tpm -ErrorAction Stop
            $tpmPresent = [bool]$t.TpmPresent
            $tpmReady   = [bool]$t.TpmReady
        } catch { }
    }

    $bitlocker = @()
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            foreach ($b in @(Get-BitLockerVolume -ErrorAction Stop)) {
                $bitlocker += [pscustomobject]@{
                    mount_point = [string]$b.MountPoint
                    protection  = [string]$b.ProtectionStatus
                    method      = [string]$b.EncryptionMethod
                    percent     = [int]$b.EncryptionPercentage
                }
            }
        } catch { }
    }

    # Looked up by SID: the built-in Administrators group is renamed on localized
    # Windows, so the display name is not an address.
    $admins = @()
    try {
        $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        foreach ($m in @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)) {
            $admins += [string]$m.Name
        }
    } catch { }

    $data = [pscustomobject]@{
        defender        = $defender
        firewall        = @($firewall)
        rdp_enabled     = $rdpEnabled
        rdp_nla         = $rdpNla
        uac_enabled     = $uacEnabled
        uac_prompt      = $uacPrompt
        smb1_enabled    = $smb1
        secure_boot     = $secureBoot
        tpm_present     = $tpmPresent
        tpm_ready       = $tpmReady
        bitlocker       = @($bitlocker)
        local_admins    = @($admins)
    }

    $lines = @()
    if ($defender.available) {
        $lines += ("defender   real-time={0} signatures {1}d old tamper={2} threats={3}" -f `
            $defender.real_time, $defender.signature_age_days, $defender.tamper_protected, @($defender.threats).Count)
    } else {
        $lines += 'defender   not available on this host'
    }
    foreach ($f in $firewall) {
        $lines += ("firewall   {0,-8} enabled={1} default-inbound={2}" -f $f.profile, $f.enabled, $f.default_inbound)
    }
    $lines += ("rdp        enabled={0} nla={1}" -f $rdpEnabled, $rdpNla)
    $lines += ("uac        enabled={0} admin-prompt={1}" -f $uacEnabled, $uacPrompt)
    $lines += ("smb1       enabled={0}   secure-boot={1}   tpm present={2} ready={3}" -f $smb1, $secureBoot, $tpmPresent, $tpmReady)
    foreach ($b in $bitlocker) {
        $lines += ("bitlocker  {0} {1} {2} {3}%" -f $b.mount_point, $b.protection, $b.method, $b.percent)
    }
    if ($admins.Count -gt 0) {
        $lines += 'local admins: ' + ($admins -join ', ')
    }

    return @{ Summary = ($lines -join "`n"); Data = $data }
}

#endregion

#region ---------------------------------------------------------------- dispatch

function Invoke-WbTool {
    param(
        [Parameter(Mandatory)][string]$Name,
        $ToolArgs,
        [switch]$IncludeWrite
    )

    $tool = Find-WbTool -Name $Name -IncludeWrite:$IncludeWrite
    if ($null -eq $tool) { throw "unknown tool: $Name" }

    $result = & $tool.handler $ToolArgs
    if ($null -eq $result -or -not $result.ContainsKey('Summary')) {
        throw "$Name returned no result object"
    }
    return $result
}

# Every tool runs in a child process of this same script.
#
# The isolation is the point: a tool that writes to the host stream, throws, or
# hangs cannot corrupt the protocol stream or wedge the session, and a timeout
# becomes possible at all. The child gets its request through the environment, so
# no argument ever has to survive command-line quoting.
function Invoke-WbToolIsolated {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$ToolArgsJson = '{}',
        [switch]$IncludeWrite
    )

    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = 'powershell.exe' }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $exe
    $psi.Arguments              = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -RunFromEnv'
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardErrorEncoding  = New-Object System.Text.UTF8Encoding($false)
    $psi.EnvironmentVariables['WINBOX_RUN_TOOL'] = $Name
    $psi.EnvironmentVariables['WINBOX_ARGS']     = $ToolArgsJson
    if ($IncludeWrite) { $psi.EnvironmentVariables['WINBOX_ALLOW_WRITE'] = '1' }

    $proc = [System.Diagnostics.Process]::Start($psi)
    # The child must not inherit this server's stdin: that stream is the protocol.
    $proc.StandardInput.Close()

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch { }
        throw "tool '$Name' timed out after $TimeoutSeconds seconds"
    }
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result

    $json = ''
    foreach ($line in @($stdout -split "`r?`n")) {
        if ($line.Trim() -ne '') { $json = $line.Trim() }
    }
    if ($json -eq '') {
        $detail = ($stderr.Trim() -split "`r?`n" | Select-Object -First 3) -join ' | '
        throw "tool '$Name' printed nothing (exit $($proc.ExitCode)) $detail"
    }

    try {
        $parsed = ConvertFrom-Json -InputObject $json
    } catch {
        throw "tool '$Name' did not return JSON: $($json.Substring(0, [Math]::Min(200, $json.Length)))"
    }
    if ($parsed.PSObject.Properties.Name -contains 'Error') { throw [string]$parsed.Error }
    return $parsed
}

function Invoke-WbRequest {
    param(
        [Parameter(Mandatory)]$Message,
        [switch]$IncludeWrite
    )

    $hasId = $Message.PSObject.Properties.Name -contains 'id'
    $id    = $null
    if ($hasId) { $id = $Message.id }

    $method = ''
    if ($Message.PSObject.Properties.Name -contains 'method') { $method = [string]$Message.method }

    switch ($method) {
        'initialize' {
            $protocol = $script:DefaultProtocol
            if ($Message.params -and $Message.params.protocolVersion) { $protocol = [string]$Message.params.protocolVersion }
            return @{
                jsonrpc = '2.0'
                id      = $id
                result  = @{
                    protocolVersion = $protocol
                    capabilities    = @{ tools = @{ listChanged = $false } }
                    serverInfo      = @{ name = $script:ServerName; version = $script:ServerVersion }
                }
            }
        }

        'notifications/initialized' { return $null }

        'ping' { return @{ jsonrpc = '2.0'; id = $id; result = @{} } }

        'tools/list' {
            $listed = @()
            foreach ($t in (Get-WbToolRegistry -IncludeWrite:$IncludeWrite)) {
                $listed += @{ name = $t.name; description = $t.description; inputSchema = $t.schema }
            }
            return @{ jsonrpc = '2.0'; id = $id; result = @{ tools = $listed } }
        }

        'tools/call' {
            $name = ''
            if ($Message.params -and $Message.params.name) { $name = [string]$Message.params.name }

            $argsJson = '{}'
            if ($Message.params -and $null -ne $Message.params.arguments) {
                $argsJson = ConvertTo-Json -InputObject $Message.params.arguments -Depth 8 -Compress
            }

            $tool = Find-WbTool -Name $name -IncludeWrite:$IncludeWrite
            if ($null -eq $tool) {
                $known = (Get-WbToolRegistry -IncludeWrite:$IncludeWrite | ForEach-Object { $_.name }) -join ', '
                return @{ jsonrpc = '2.0'; id = $id; result = (New-ToolError "unknown tool '$name'. Available: $known") }
            }

            try {
                $out = Invoke-WbToolIsolated -Name $name -ToolArgsJson $argsJson -IncludeWrite:$IncludeWrite
                return @{ jsonrpc = '2.0'; id = $id; result = (New-TextResult -Text $out.Summary -Data $out.Data) }
            } catch {
                return @{ jsonrpc = '2.0'; id = $id; result = (New-ToolError $_.Exception.Message) }
            }
        }

        default {
            # A notification (no id) is never answered, not even when unknown.
            if (-not $hasId) { return $null }
            return @{
                jsonrpc = '2.0'
                id      = $id
                error   = @{ code = -32601; message = "method not found: $method" }
            }
        }
    }
}

function Start-WbServer {
    param([switch]$IncludeWrite)

    $stdin = [Console]::In
    while ($null -ne ($line = $stdin.ReadLine())) {
        $line = $line.Trim()
        if ($line -eq '') { continue }

        try {
            $message = ConvertFrom-Json -InputObject $line
        } catch {
            Write-Frame @{ jsonrpc = '2.0'; id = $null; error = @{ code = -32700; message = 'parse error' } }
            continue
        }

        try {
            $response = Invoke-WbRequest -Message $message -IncludeWrite:$IncludeWrite
        } catch {
            $id = $null
            if ($message.PSObject.Properties.Name -contains 'id') { $id = $message.id }
            $response = @{ jsonrpc = '2.0'; id = $id; error = @{ code = -32603; message = $_.Exception.Message } }
        }

        if ($null -ne $response) { Write-Frame $response }
    }
}

#endregion

#region -------------------------------------------------------------- entry points

function Invoke-WbSelfTest {
    $ok = 0
    $bad = 0
    foreach ($t in (Get-WbToolRegistry)) {
        try {
            $out = Invoke-WbTool -Name $t.name -ToolArgs $null
            $first = ($out.Summary -split "`n")[0]
            Write-Host ('  [ ok ] ' + $t.name.PadRight(16) + $first) -ForegroundColor Green
            $ok++
        } catch {
            Write-Host ('  [fail] ' + $t.name.PadRight(16) + $_.Exception.Message) -ForegroundColor Red
            $bad++
        }
    }
    Write-Host ''
    Write-Host "$ok ok, $bad failed"
    if ($bad -gt 0) { exit 1 }
}

function Invoke-WbMain {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

    if ($RunFromEnv) {
        # Child process: one tool, one JSON line, nothing else on stdout.
        try {
            $includeWrite = $env:WINBOX_ALLOW_WRITE -eq '1'
            $toolArgs = $null
            if ($env:WINBOX_ARGS) { $toolArgs = ConvertFrom-Json -InputObject $env:WINBOX_ARGS }
            $out = Invoke-WbTool -Name $env:WINBOX_RUN_TOOL -ToolArgs $toolArgs -IncludeWrite:$includeWrite
            [Console]::Out.WriteLine((ConvertTo-Json -InputObject $out -Depth 12 -Compress))
        } catch {
            [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ Error = $_.Exception.Message } -Compress))
            exit 1
        }
        return
    }

    if ($ListTools) {
        $listed = @()
        foreach ($t in (Get-WbToolRegistry -IncludeWrite:$AllowWrite)) {
            $listed += @{ name = $t.name; description = $t.description; inputSchema = $t.schema }
        }
        Write-Output (ConvertTo-Json -InputObject $listed -Depth 12)
        return
    }

    if ($SelfTest) {
        Invoke-WbSelfTest
        return
    }

    if ($RunTool) {
        # -ArgsJson is JSON on a command line, and Windows PowerShell 5.1 mangles
        # the quotes of an argument passed to a native command. WINBOX_ARGS is the
        # escape hatch: set it and pass no -ArgsJson at all.
        $json = $ArgsJson
        if (-not $PSBoundParameters.ContainsKey('ArgsJson') -and $env:WINBOX_ARGS) {
            $json = $env:WINBOX_ARGS
        }
        $toolArgs = $null
        if ($json) { $toolArgs = ConvertFrom-Json -InputObject $json }
        $out = Invoke-WbTool -Name $RunTool -ToolArgs $toolArgs -IncludeWrite:$AllowWrite
        Write-Output (ConvertTo-Json -InputObject $out -Depth 12)
        return
    }

    Start-WbServer -IncludeWrite:$AllowWrite
}

#endregion

if ($MyInvocation.InvocationName -ne '.') { Invoke-WbMain }
