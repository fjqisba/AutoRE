[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$DeployDir = $PSScriptRoot
$RuntimeDir = Join-Path $DeployDir 'runtime'
$PgDataDir = Join-Path $RuntimeDir 'postgres-data'
$PgBinDir = Join-Path $DeployDir 'pgsql\bin'
$PgCtl = Join-Path $PgBinDir 'pg_ctl.exe'
$PgIsReady = Join-Path $PgBinDir 'pg_isready.exe'
$LumenExe = Join-Path $DeployDir 'bin\lumen.exe'
$ConfigPath = Join-Path $DeployDir 'config.toml'
$SecretPath = Join-Path $RuntimeDir 'lumen.env'
$LumenPidPath = Join-Path $RuntimeDir 'lumen.pid'
$PostgresPidPath = Join-Path $RuntimeDir 'postgres.pid'

function Get-VerifiedProcess {
    param(
        [Parameter(Mandatory)] [string] $PidFile,
        [Parameter(Mandatory)] [string] $ExpectedPath
    )

    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) {
        return $null
    }

    $savedPid = 0
    if (-not [int]::TryParse((Get-Content -LiteralPath $PidFile -Raw).Trim(), [ref] $savedPid)) {
        Remove-Item -LiteralPath $PidFile -Force
        return $null
    }

    $process = Get-Process -Id $savedPid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $PidFile -Force
        return $null
    }

    try {
        $actualPath = [IO.Path]::GetFullPath($process.Path)
    }
    catch {
        return $null
    }

    if (-not $actualPath.Equals([IO.Path]::GetFullPath($ExpectedPath), [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }

    return $process
}

function Assert-PortAvailable {
    param([Parameter(Mandatory)] [int] $Port)

    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        $owners = ($listeners | Select-Object -ExpandProperty OwningProcess -Unique) -join ', '
        throw "TCP 端口 $Port 已被其他进程占用（PID: $owners）。"
    }
}

foreach ($requiredPath in @($PgCtl, $PgIsReady, $LumenExe, $ConfigPath, $SecretPath, $PgDataDir)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "缺少必需文件或目录：$requiredPath"
    }
}

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

& $PgCtl status -D $PgDataDir *> $null
if ($LASTEXITCODE -ne 0) {
    Assert-PortAvailable -Port 5432
    $pgLog = Join-Path $RuntimeDir 'postgresql.log'
    & $PgCtl start -D $PgDataDir -l $pgLog -o '-h 127.0.0.1 -p 5432' -w
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL 启动失败，请检查 $pgLog"
    }
}

$postmasterPid = Join-Path $PgDataDir 'postmaster.pid'
if (Test-Path -LiteralPath $postmasterPid -PathType Leaf) {
    (Get-Content -LiteralPath $postmasterPid -TotalCount 1).Trim() |
        Set-Content -LiteralPath $PostgresPidPath -Encoding ascii -NoNewline
}

& $PgIsReady -h 127.0.0.1 -p 5432 *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'PostgreSQL 尚未准备好接受连接。'
}

$existingLumen = Get-VerifiedProcess -PidFile $LumenPidPath -ExpectedPath $LumenExe
if ($null -ne $existingLumen) {
    Write-Host "Lumen 已在运行（PID $($existingLumen.Id)）。"
    exit 0
}

Assert-PortAvailable -Port 1234
Assert-PortAvailable -Port 8082

$secretValues = ConvertFrom-StringData (Get-Content -LiteralPath $SecretPath -Raw)
if ([string]::IsNullOrWhiteSpace($secretValues.PKCSPASSWD)) {
    throw "启动凭据文件无效：$SecretPath"
}

$stdoutLog = Join-Path $RuntimeDir 'lumen.stdout.log'
$stderrLog = Join-Path $RuntimeDir 'lumen.stderr.log'
$lumenProcess = Start-Process -FilePath $LumenExe `
    -ArgumentList @('-c', 'config.toml') `
    -WorkingDirectory $DeployDir `
    -Environment @{ PKCSPASSWD = $secretValues.PKCSPASSWD } `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -WindowStyle Hidden `
    -PassThru
$lumenProcess.Id | Set-Content -LiteralPath $LumenPidPath -Encoding ascii -NoNewline

$deadline = [DateTime]::UtcNow.AddSeconds(20)
do {
    Start-Sleep -Milliseconds 250
    $lumenProcess.Refresh()
    if ($lumenProcess.HasExited) {
        throw "Lumen 启动后退出，请检查 $stderrLog"
    }
    $luminaReady = @(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort 1234 -ErrorAction SilentlyContinue).Count -gt 0
    $apiReady = @(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort 8082 -ErrorAction SilentlyContinue).Count -gt 0
} until (($luminaReady -and $apiReady) -or [DateTime]::UtcNow -ge $deadline)

if (-not ($luminaReady -and $apiReady)) {
    throw "Lumen 未在预期时间内监听 127.0.0.1:1234 和 127.0.0.1:8082，请检查 $stderrLog"
}

Write-Host "Lumen 已启动（PID $($lumenProcess.Id)），地址 127.0.0.1:1234。"

