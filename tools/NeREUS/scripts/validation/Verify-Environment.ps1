#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../build/Enter-Environment.ps1')
Set-Location $nereusRoot

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program 执行失败，退出码 $LASTEXITCODE" }
}

Invoke-Checked cargo @('fmt','--all','--','--check')
Invoke-Checked cargo @('clippy','--workspace','--all-targets','--locked','--','-D','warnings')
Invoke-Checked cargo @('test','--workspace','--locked')
Invoke-Checked cargo @('run','--locked','-p','nereus-cli','--','doctor')
Invoke-Checked cargo @('run','--locked','-p','nereus-cli','--','lift-instruction','--bytes','4801d8','--out','temp_data/validation/cli-lift')

# 求解 BV 恒等式的反例查询；UNSAT 检查真实求解能力，而不只是可执行文件存在。
$smtPath = Join-Path $nereusRoot 'temp_data/validation/wrapping-add.smt2'
@'
(set-logic QF_BV)
(declare-const x (_ BitVec 64))
(declare-const y (_ BitVec 64))
(assert (not (= (bvadd x y) (bvadd y x))))
(check-sat)
'@ | Set-Content $smtPath -Encoding ascii
$solverOutput = & $env:NEREUS_Z3 $smtPath
if ($LASTEXITCODE -ne 0 -or $solverOutput.Trim() -ne 'unsat') { throw "Z3 求解验证失败：$solverOutput" }

& (Join-Path $PSScriptRoot '../build/Write-Manifest.ps1')
Write-Host '环境验证通过：Rust、LLVM 静态链接、Remill worker、bitcode 往返和 Z3。'
