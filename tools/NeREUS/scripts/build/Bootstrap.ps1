#Requires -Version 7.0
param([int]$Jobs = 6, [switch]$SkipNative, [switch]$SkipRust, [switch]$UseProxy)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Enter-Environment.ps1') -UseProxy:$UseProxy
Set-Location $nereusRoot
$lock = Get-Content toolchains/versions.lock.json -Raw | ConvertFrom-Json

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program 执行失败，退出码 $LASTEXITCODE" }
}

New-Item -ItemType Directory -Force temp_data/bootstrap, toolchains/bin, third_party | Out-Null
if (-not $SkipNative) {
    if (-not (Test-Path third_party/remill/.git)) {
        Invoke-Checked git @('clone','--filter=blob:none','--no-checkout',$lock.remill.repository,'third_party/remill')
        Invoke-Checked git @('-C','third_party/remill','checkout','--detach',$lock.remill.revision)
    }
    $revision = & git -C third_party/remill rev-parse HEAD
    if ($revision.Trim() -ne $lock.remill.revision) { throw 'Remill revision 与锁定文件不同，拒绝覆盖现有源码。' }
    # 已应用的补丁按反向检查识别；未知源码修改不能被静默覆盖。
    $patchPath = Join-Path $nereusRoot $lock.remill.patch
    & git -C third_party/remill apply --reverse --check $patchPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Checked git @('-C','third_party/remill','apply','--check',$patchPath)
        Invoke-Checked git @('-C','third_party/remill','apply',$patchPath)
    }
    $depsPrefix = Join-Path $nereusRoot 'toolchains/remill-deps-clang19'
    $llvmCmake = Join-Path $nereusLocal.llvm_root 'lib/cmake/llvm'
    $common = @('-G','Ninja',"-DCMAKE_MAKE_PROGRAM=$($nereusLocal.ninja)",
        "-DCMAKE_C_COMPILER=$($nereusLocal.host_clang)","-DCMAKE_CXX_COMPILER=$($nereusLocal.host_clang)",
        '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.21',"-DLLVM_DIR=$llvmCmake")
    Invoke-Checked cmake (@('-S','third_party/remill/dependencies','-B','temp_data/bootstrap/dependencies-clang19',
        '-DUSE_EXTERNAL_LLVM=ON',"-DCMAKE_INSTALL_PREFIX=$depsPrefix", "-DPython3_EXECUTABLE=$($nereusLocal.python)") + $common)
    Invoke-Checked cmake @('--build','temp_data/bootstrap/dependencies-clang19','--parallel',"$Jobs")
    $prefixes = "$depsPrefix;$($nereusLocal.llvm_root)"
    Invoke-Checked cmake (@('-S','third_party/remill','-B','temp_data/bootstrap/remill',
        "-DCMAKE_PREFIX_PATH=$prefixes", "-DCLANG_PATH=$($nereusLocal.semantics_clang)",
        '-DREMILL_X86_ONLY=ON','-DREMILL_ENABLE_TESTING=OFF',
        "-DCMAKE_INSTALL_PREFIX=$nereusRoot/toolchains/remill-install") + $common)
    Invoke-Checked cmake @('--build','temp_data/bootstrap/remill','--parallel',"$Jobs")
    Invoke-Checked cmake @('--install','temp_data/bootstrap/remill')
    Invoke-Checked cmake (@('-S','native/remill-worker','-B','temp_data/bootstrap/worker',
        "-DCMAKE_PREFIX_PATH=$nereusRoot/toolchains/remill-install;$prefixes", "-DCMAKE_INSTALL_PREFIX=$nereusRoot/toolchains") + $common)
    Invoke-Checked cmake @('--build','temp_data/bootstrap/worker','--parallel',"$Jobs")
    Invoke-Checked cmake @('--install','temp_data/bootstrap/worker')
}
if (-not $SkipRust) {
    $installedToolchains = (& rustup toolchain list) -join "`n"
    if ($installedToolchains -notmatch ('(?m)^' + [regex]::Escape($lock.rust + '-x86_64-pc-windows-msvc') + '(\s|$)')) {
        # 先完成固定 toolchain 的安装，再启动 Cargo，避免隐式自动安装竞争。
        Invoke-Checked rustup @('toolchain','install',$lock.rust,'--profile','minimal','--component','rustfmt','--component','clippy','--no-self-update')
    }
    Invoke-Checked cargo @('build','--workspace','--locked')
}
& (Join-Path $PSScriptRoot 'Write-Manifest.ps1')
