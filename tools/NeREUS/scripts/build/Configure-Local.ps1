#Requires -Version 7.0
param(
    [string]$LLVMRoot,
    [string]$SemanticsClang,
    [string]$HostClang,
    [string]$Ninja,
    [string]$Python,
    [string]$Z3,
    [string]$GraphvizDot,
    [string]$Proxy = 'http://127.0.0.1:7897'
)
$ErrorActionPreference = 'Stop'
$nereusRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path $vswhere)) { throw '未找到 vswhere，请安装 Visual Studio C++ 工具。' }
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw '未找到含 x64 C++ 工具的 Visual Studio。' }
if (-not $LLVMRoot) { $LLVMRoot = Split-Path (Split-Path (Get-Command llvm-config -ErrorAction Stop).Source) }
if (-not $HostClang) { $HostClang = Join-Path $vsRoot 'VC/Tools/Llvm/x64/bin/clang-cl.exe' }
if (-not $SemanticsClang) { $SemanticsClang = (Get-Command clang -ErrorAction Stop).Source }
if (-not $Ninja) { $Ninja = (Get-Command ninja -ErrorAction Stop).Source }
if (-not $Python) { $Python = (Get-Command python -ErrorAction Stop).Source }
if (-not $Z3) { $Z3 = (Get-Command z3 -ErrorAction Stop).Source }
$config = [ordered]@{
    schema_version = 1; visual_studio = $vsRoot; llvm_root = $LLVMRoot
    semantics_clang = $SemanticsClang; host_clang = $HostClang
    ninja = $Ninja; python = $Python; z3 = $Z3; proxy = $Proxy
}
$existingConfig=Join-Path $nereusRoot 'toolchains/local.json'
if(-not $GraphvizDot -and (Test-Path $existingConfig)){
    $previous=Get-Content $existingConfig -Raw|ConvertFrom-Json
    if($previous.PSObject.Properties['graphviz_dot']){$GraphvizDot=$previous.graphviz_dot}
}
if(-not $GraphvizDot){$command=Get-Command dot -ErrorAction SilentlyContinue;if($command){$GraphvizDot=$command.Source}}
if($GraphvizDot){
    if(-not(Test-Path -LiteralPath $GraphvizDot)){throw 'GraphvizDot 路径无效'}
    $config.graphviz_dot=$GraphvizDot
}
foreach ($name in @('llvm_root','semantics_clang','host_clang','ninja','python','z3')) {
    if (-not (Test-Path -LiteralPath $config[$name])) { throw "无效工具路径 $name : $($config[$name])" }
}
# 本机绝对路径只进入已忽略的 local.json，不写入共享构建文件。
$config | ConvertTo-Json | Set-Content (Join-Path $nereusRoot 'toolchains/local.json') -Encoding utf8
Write-Host '已写入 toolchains/local.json。'
