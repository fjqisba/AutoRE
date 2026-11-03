#Requires -Version 7.0
param([switch]$UseProxy)
$ErrorActionPreference = 'Stop'
$nereusRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$nereusLocalFile = Join-Path $nereusRoot 'toolchains/local.json'
if (-not (Test-Path $nereusLocalFile)) { throw '请先运行 scripts/build/Configure-Local.ps1。' }
$nereusLocal = Get-Content $nereusLocalFile -Raw | ConvertFrom-Json
$devShell = Join-Path $nereusLocal.visual_studio 'Common7/Tools/Launch-VsDevShell.ps1'
& $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
if (-not $env:VCToolsInstallDir) { throw 'Visual Studio 开发环境初始化失败。' }
$env:NEREUS_ROOT = $nereusRoot
$env:LLVM_SYS_170_PREFIX = $nereusLocal.llvm_root
$env:NEREUS_Z3 = $nereusLocal.z3
$nereusToolDirs = @(
    (Join-Path $nereusLocal.llvm_root 'bin'),
    (Split-Path $nereusLocal.host_clang),
    (Split-Path $nereusLocal.ninja),
    (Split-Path $nereusLocal.python)
)
$env:PATH = ($nereusToolDirs -join ';') + ';' + $env:PATH
# 代理仅影响当前进程及其子进程，不修改系统/用户代理或 Git 全局配置。
if ($UseProxy -and $nereusLocal.proxy) {
    $env:HTTP_PROXY = $nereusLocal.proxy
    $env:HTTPS_PROXY = $nereusLocal.proxy
}
$nereusVersions = Get-Content (Join-Path $nereusRoot 'toolchains/versions.lock.json') -Raw | ConvertFrom-Json
$nereusLlvmActual = & (Join-Path $nereusLocal.llvm_root 'bin/llvm-config.exe') --version
if ($LASTEXITCODE -ne 0 -or $nereusLlvmActual.Trim() -ne $nereusVersions.llvm) { throw 'LLVM 版本与 versions.lock.json 不匹配。' }
foreach ($nereusCheck in @(
    @{ path = $nereusLocal.semantics_clang; version = $nereusVersions.semantics_clang },
    @{ path = $nereusLocal.host_clang; version = $nereusVersions.host_clang }
)) {
    $nereusActual = (& $nereusCheck.path --version) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $nereusActual -notmatch ('clang version ' + [regex]::Escape($nereusCheck.version) + '(\s|$)')) {
        throw "Clang 版本不匹配：$($nereusCheck.path)"
    }
}
