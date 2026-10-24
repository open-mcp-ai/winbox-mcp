# tests/smoke.ps1 - the protocol contract, asserted.
#
# Drives the server over stdio exactly as a client does: a batch of frames in,
# one JSON reply per frame with an id out. No Pester and no Windows-specific
# tool, so this runs in CI on Linux, macOS and Windows.
#
#   pwsh -NoProfile -File tests/smoke.ps1

[CmdletBinding()]
param(
    [string]$ServerPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'winbox-mcp.ps1')
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0

function Assert-That {
    param([string]$What, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        $script:Pass++
        Write-Host ("  [ ok ] " + $What) -ForegroundColor Green
    } else {
        $script:Fail++
        Write-Host ("  [fail] " + $What + $(if ($Detail) { " -> $Detail" })) -ForegroundColor Red
    }
}

function Get-Exe {
    foreach ($c in @('pwsh', 'pwsh.exe', 'powershell.exe')) {
        $p = Get-Command $c -ErrorAction SilentlyContinue
        if ($p) { return $p.Source }
    }
    throw 'no PowerShell found'
}

# Feeds frames in and returns the parsed replies. The child is given the whole
# batch at once and its output read to the end, so the test never has to guess
# how long a tool takes.
function Invoke-Frames {
    param([string[]]$Frames, [switch]$AllowWrite)

    $exe = Get-Exe
    $args = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ServerPath)
    if ($AllowWrite) { $args += '-AllowWrite' }

    $text = ($Frames -join "`n") + "`n"
    $raw = $text | & $exe @args 2>$null

    $replies = @()
    foreach ($line in @($raw)) {
        $line = ([string]$line).Trim()
        if ($line -eq '') { continue }
        $replies += (ConvertFrom-Json -InputObject $line)
    }
    return $replies
}

function Find-Reply {
    param($Replies, $Id)
    foreach ($r in $Replies) {
        if ($r.PSObject.Properties.Name -contains 'id' -and $r.id -eq $Id) { return $r }
    }
    return $null
}

if (-not (Test-Path -LiteralPath $ServerPath)) {
    throw "server not found: $ServerPath"
}

Write-Host "winbox-mcp smoke test"
Write-Host "  server: $ServerPath"
Write-Host "  host:   $([System.Environment]::OSVersion.Platform)"
Write-Host ''

# --- the handshake, the catalogue, and the frames that must NOT be answered ----
$replies = Invoke-Frames -Frames @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    '{"jsonrpc":"2.0","id":3,"method":"ping"}'
)

Assert-That 'initialize is answered' ($null -ne (Find-Reply $replies 1))
$init = Find-Reply $replies 1
Assert-That 'initialize names the server' ($init.result.serverInfo.name -eq 'winbox-mcp')
Assert-That 'initialize echoes the protocol version' ($init.result.protocolVersion -eq '2024-11-05')
Assert-That 'initialize advertises tools' ($null -ne $init.result.capabilities.tools)
Assert-That 'a notification is not answered' ($null -eq (Find-Reply $replies 'initialized'))
Assert-That 'one reply per frame with an id' ($replies.Count -eq 3)

$list = Find-Reply $replies 2
$names = @($list.result.tools | ForEach-Object { $_.name })
$expected = @(
    'host_info', 'resources', 'volumes', 'processes', 'services', 'listening_ports',
    'event_log', 'scheduled_tasks', 'updates', 'security_posture'
)
Assert-That 'tools/list returns the read-only catalogue' (($names -join ',') -eq ($expected -join ',')) ($names -join ',')

$write = @('service_control', 'kill_process')
foreach ($w in $write) {
    Assert-That "tools/list hides $w without -AllowWrite" ($names -notcontains $w)
}

$everyToolHasSchema = $true
foreach ($t in $list.result.tools) {
    if ($null -eq $t.inputSchema -or $t.inputSchema.type -ne 'object') { $everyToolHasSchema = $false }
    if ([string]::IsNullOrWhiteSpace($t.description)) { $everyToolHasSchema = $false }
}
Assert-That 'every tool has an object schema and a description' $everyToolHasSchema

$pong = Find-Reply $replies 3
Assert-That 'ping is answered with an empty result' ($null -ne $pong.result)

# --- -AllowWrite publishes the mutating tools, and only then -------------------
$repliesWrite = Invoke-Frames -AllowWrite -Frames @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
)
$namesWrite = @((Find-Reply $repliesWrite 2).result.tools | ForEach-Object { $_.name })
foreach ($w in $write) {
    Assert-That "-AllowWrite publishes $w" ($namesWrite -contains $w)
}
Assert-That '-AllowWrite keeps the read-only tools' ($namesWrite -contains 'host_info')

# --- failures are answers, not crashes ----------------------------------------
$repliesBad = Invoke-Frames -Frames @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    'this is not json'
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope","arguments":{}}}'
    '{"jsonrpc":"2.0","id":3,"method":"no/such/method"}'
    '{"jsonrpc":"2.0","method":"no/such/notification"}'
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"processes","arguments":{"sort":"bogus"}}}'
    '{"jsonrpc":"2.0","id":5,"method":"tools/list"}'
)

$parseErr = $null
foreach ($r in $repliesBad) {
    if ($r.PSObject.Properties.Name -contains 'error' -and $r.error.code -eq -32700) { $parseErr = $r }
}
Assert-That 'malformed input answers a parse error' ($null -ne $parseErr)
Assert-That 'a parse error carries a null id' ($null -ne $parseErr -and $null -eq $parseErr.id)

$unknownTool = Find-Reply $repliesBad 2
Assert-That 'an unknown tool is a tool error, not a protocol error' ($unknownTool.result.isError -eq $true)
Assert-That 'the unknown-tool error lists what exists' ($unknownTool.result.content[0].text -match 'unknown tool')

$unknownMethod = Find-Reply $repliesBad 3
Assert-That 'an unknown method answers -32601' ($unknownMethod.error.code -eq -32601)

$badArg = Find-Reply $repliesBad 4
Assert-That 'a bad argument is rejected before it reaches the host' ($badArg.result.isError -eq $true)
Assert-That 'the rejection names the argument' ($badArg.result.content[0].text -match 'sort must be')

Assert-That 'an unknown notification is not answered' ($null -eq (Find-Reply $repliesBad 'no/such/notification'))

$stillAlive = Find-Reply $repliesBad 5
Assert-That 'the server survives all of that' ($null -ne $stillAlive.result.tools)

Write-Host ''
Write-Host "$script:Pass passed, $script:Fail failed"
if ($script:Fail -gt 0) { exit 1 }
