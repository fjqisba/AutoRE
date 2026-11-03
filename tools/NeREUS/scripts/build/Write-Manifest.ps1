#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
$nereusRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$lock = Get-Content (Join-Path $nereusRoot 'toolchains/versions.lock.json') -Raw | ConvertFrom-Json
$localTools = Get-Content (Join-Path $nereusRoot 'toolchains/local.json') -Raw | ConvertFrom-Json
$semanticsDir = Join-Path $nereusRoot 'toolchains/remill-install/share/remill/17/semantics'
$semanticsFiles = @(Get-ChildItem $semanticsDir -Filter '*.bc' | Sort-Object Name | ForEach-Object {
    [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$patchPath = Join-Path $nereusRoot $lock.remill.patch
$dependencySources = [ordered]@{}
foreach ($depName in @('gflags','glog','googletest','mbuild','xed')) {
    $prefixName = if ($depName -eq 'mbuild') { 'xed' } else { $depName }
    $sourceDir = Join-Path $nereusRoot "temp_data/bootstrap/dependencies-clang19/$prefixName-prefix/src/$depName"
    $depRevision = (& git -C $sourceDir rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $depRevision -ne $lock.dependency_revisions.$depName) { throw "依赖版本不匹配：$depName" }
    $dependencySources[$depName] = $depRevision
}
$llvmActual = (& (Join-Path $localTools.llvm_root 'bin/llvm-config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $llvmActual -ne $lock.llvm) { throw '实际 LLVM 版本与锁定值不匹配。' }
$manifest = [ordered]@{
    schema_version = 1; generated_at_utc = [DateTime]::UtcNow.ToString('o')
    remill_revision = (& git -C (Join-Path $nereusRoot 'third_party/remill') rev-parse HEAD).Trim()
    patch_sha256 = (Get-FileHash $patchPath -Algorithm SHA256).Hash.ToLowerInvariant()
    worker_sha256 = (Get-FileHash (Join-Path $nereusRoot 'toolchains/bin/nereus-remill-worker.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    llvm = $llvmActual; semantics_clang = $lock.semantics_clang; host_clang = $lock.host_clang
    dependency_revisions = $dependencySources
    state_header_sha256 = (Get-FileHash (Join-Path $nereusRoot 'third_party/remill/include/remill/Arch/X86/Runtime/State.h') -Algorithm SHA256).Hash.ToLowerInvariant()
    host = 'x86_64-pc-windows-msvc'; crt = $lock.crt; protocol_version = $lock.protocol_version
    semantics = $semanticsFiles; nir_import_implemented = $false; behavior_equivalence_verified = $false
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $nereusRoot 'toolchains/semantics.manifest.json') -Encoding utf8
