#Requires -Version 5.1
<#
.SYNOPSIS
启动官方 Hex-Rays IDA MCP，默认以本机 HTTP 服务运行。
.EXAMPLE
.\Start-IdaMcp.ps1
.EXAMPLE
.\Start-IdaMcp.ps1 -Database 'D:\samples\sample.exe'
.EXAMPLE
.\Start-IdaMcp.ps1 -OpenIda -Database 'D:\samples\sample.i64'
.EXAMPLE
.\Start-IdaMcp.ps1 -Mode Stdio
#>
[CmdletBinding()]
param(
    [ValidateSet('Http', 'Stdio', 'Dashboard')]
    [string]$Mode = 'Http',
    [string]$IdaDirectory = 'D:\Crack Tools\IDA Professional 9.5',
    [string]$McpExecutable,
    [string]$Database,
    [ValidateRange(1, 65535)]
    [int]$Port = 8737,
    [string]$Agent = 'powershell',
    [ValidateRange(0, 2147483647)]
    [int]$IdleTimeout = 0,
    [switch]$OpenIda
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    # 固定 IDA 安装位置，GUI 和 headless worker 均继承这一环境变量。
    $IdaDirectory = (Resolve-Path -LiteralPath $IdaDirectory).Path
    foreach ($file in @('ida.exe', 'idalib.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $IdaDirectory $file) -PathType Leaf)) {
            throw "IDA 目录缺少 ${file}：$IdaDirectory"
        }
    }
    $env:IDADIR = $IdaDirectory
    $env:PYTHONUTF8 = '1'

    # 优先使用 uv 已安装的官方可执行文件，不在每次启动时联网安装。
    if (-not $McpExecutable) {
        $candidate = Join-Path $env:USERPROFILE '.local\bin\ida-mcp.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $McpExecutable = $candidate
        } else {
            $command = Get-Command 'ida-mcp' -ErrorAction SilentlyContinue
            if ($command) { $McpExecutable = $command.Source }
        }
    }
    if (-not $McpExecutable -or -not (Test-Path -LiteralPath $McpExecutable -PathType Leaf)) {
        throw '未找到官方 ida-mcp。请先运行 uv tool install ida-mcp，或使用 -McpExecutable 指定已安装的程序。'
    }
    $McpExecutable = (Resolve-Path -LiteralPath $McpExecutable).Path

    if ($Database) {
        $Database = (Resolve-Path -LiteralPath $Database).Path
        if (-not (Test-Path -LiteralPath $Database -PathType Leaf)) {
            throw "数据库或二进制文件不是普通文件：$Database"
        }
    }
    if ($Mode -eq 'Dashboard' -and ($Database -or $OpenIda)) {
        throw 'Dashboard 模式不能搭配 -Database 或 -OpenIda。'
    }
    if ($OpenIda -and -not $Database) {
        throw '-OpenIda 需要 -Database 指定二进制或数据库文件。'
    }

    $serverArguments = @($Mode.ToLowerInvariant())
    if ($Mode -eq 'Dashboard') {
        $serverArguments += '--open'
    } else {
        $serverArguments += @('--agent', $Agent, '--idle-timeout', [string]$IdleTimeout)
        if ($Mode -eq 'Http') {
            $serverArguments += @('--host', '127.0.0.1', '--port', [string]$Port)
            $url = "http://127.0.0.1:$Port/mcp"
            $listener = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
            if ($listener.Count -gt 0) {
                # 通过 MCP 握手区分已运行的官方服务与其他占用端口的程序。
                $request = @{
                    jsonrpc = '2.0'; id = 1; method = 'initialize'
                    params = @{
                        protocolVersion = '2025-03-26'; capabilities = @{}
                        clientInfo = @{ name = 'ida-mcp-launcher'; version = '1.0' }
                    }
                } | ConvertTo-Json -Depth 6 -Compress
                try {
                    $reply = Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' `
                        -Headers @{ Accept = 'application/json, text/event-stream' } -Body $request -TimeoutSec 5
                } catch {
                    throw "端口 $Port 已被占用，且不是可响应的 IDA MCP。请使用 -Port 指定其他端口。"
                }
                if (-not $reply.PSObject.Properties['result'] -or $reply.result.serverInfo.name -ne 'ida') {
                    throw "端口 $Port 上运行的是其他服务，请使用 -Port 指定其他端口。"
                }
                if ($Database -or $OpenIda) {
                    throw "IDA MCP 已在 $url 运行。请通过客户端 open_database 打开文件，或使用其他 -Port 启动新服务。"
                }
                Write-Host "官方 IDA MCP 已在运行：$url（$($reply.result.serverInfo.version)）"
                exit 0
            }
        }
        if ($OpenIda) {
            # GUI 在分析完成后自动向 Nexus 注册；让客户端随后发现并连接。
            # 不同时传 --database，避免 GUI 初始化期间为同一文件抢先创建 headless worker。
            $idaExecutable = Join-Path $IdaDirectory 'ida.exe'
            Start-Process -FilePath $idaExecutable -ArgumentList ('"{0}"' -f $Database) `
                -WorkingDirectory (Split-Path -Parent $Database) -WindowStyle Normal | Out-Null
        } elseif ($Database) {
            $serverArguments += @('--database', $Database)
        }
    }

    # stdio 模式的标准输出仅用于 MCP 协议，禁止混入提示或进度日志。
    if ($Mode -eq 'Http') {
        Write-Host '启动官方 Hex-Rays IDA MCP'
        Write-Host "IDA：$IdaDirectory"
        Write-Host "MCP：$url"
        if ($OpenIda) {
            Write-Host '等待 IDA GUI 完成加载；客户端可用 list_databases 查看并连接数据库。'
        }
        Write-Host '按 Ctrl+C 停止此服务。'
    }
    & $McpExecutable @serverArguments
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine("IDA MCP 启动失败：$($_.Exception.Message)")
    exit 1
}
