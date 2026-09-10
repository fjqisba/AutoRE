[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$DeployDir = $PSScriptRoot
$RuntimeDir = Join-Path $DeployDir 'runtime'
$PgDataDir = Join-Path $RuntimeDir 'postgres-data'
$PgCtl = Join-Path $DeployDir 'pgsql\bin\pg_ctl.exe'
$LumenExe = Join-Path $DeployDir 'bin\lumen.exe'
$LumenPidPath = Join-Path $RuntimeDir 'lumen.pid'
$PostgresPidPath = Join-Path $RuntimeDir 'postgres.pid'

function Get-ProcessForDeployment {
    param(
        [Parameter(Mandatory)] [string] $PidFile,
        [Parameter(Mandatory)] [string] $ExpectedPath
    )

    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) {
        return $null
    }

    $savedPid = 0
    if (-not [int]::TryParse((Get-Content -LiteralPath $PidFile -Raw).Trim(), [ref] $savedPid)) {
        return $null
    }

    $process = Get-Process -Id $savedPid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }

    try {
        $actualPath = [IO.Path]::GetFullPath($process.Path)
    }
    catch {
        return $null
    }

    if ($actualPath.Equals([IO.Path]::GetFullPath($ExpectedPath), [StringComparison]::OrdinalIgnoreCase)) {
        return $process
    }

    return $null
}

$lumenProcess = Get-ProcessForDeployment -PidFile $LumenPidPath -ExpectedPath $LumenExe
if ($null -ne $lumenProcess) {
    Stop-Process -Id $lumenProcess.Id
    $lumenProcess.WaitForExit(10000) | Out-Null
    Write-Host "已停止 Lumen（PID $($lumenProcess.Id)）。"
}
elseif (Test-Path -LiteralPath $LumenPidPath -PathType Leaf) {
    Write-Warning 'Lumen PID 文件未对应本部署目录中的进程，未结束任何进程。'
}
Remove-Item -LiteralPath $LumenPidPath -Force -ErrorAction SilentlyContinue

$postgresOwned = $false
$postmasterPidPath = Join-Path $PgDataDir 'postmaster.pid'
if (Test-Path -LiteralPath $postmasterPidPath -PathType Leaf) {
    $postmasterPid = 0
    if ([int]::TryParse((Get-Content -LiteralPath $postmasterPidPath -TotalCount 1).Trim(), [ref] $postmasterPid)) {
        $postgresProcess = Get-Process -Id $postmasterPid -ErrorAction SilentlyContinue
        if ($null -ne $postgresProcess) {
            try {
                $expectedPostgres = [IO.Path]::GetFullPath((Join-Path $DeployDir 'pgsql\bin\postgres.exe'))
                $postgresOwned = [IO.Path]::GetFullPath($postgresProcess.Path).Equals($expectedPostgres, [StringComparison]::OrdinalIgnoreCase)
            }
            catch {
                $postgresOwned = $false
            }
        }
    }
}

if ($postgresOwned) {
    & $PgCtl stop -D $PgDataDir -m fast -w
    if ($LASTEXITCODE -ne 0) {
        throw 'PostgreSQL 停止失败。'
    }
    Write-Host '已停止本部署目录的 PostgreSQL。'
}
elseif (Test-Path -LiteralPath $postmasterPidPath -PathType Leaf) {
    Write-Warning 'PostgreSQL 数据目录的 PID 未对应本部署目录中的 postgres.exe，未结束任何进程。'
}
Remove-Item -LiteralPath $PostgresPidPath -Force -ErrorAction SilentlyContinue

