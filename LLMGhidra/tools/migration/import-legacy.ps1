param(
    [string]$LegacyRoot = (Join-Path $PSScriptRoot '../../../LLMGhidra1'),
    [string]$DestinationRoot = (Join-Path $PSScriptRoot '../..')
)
$ErrorActionPreference = 'Stop'
$legacy = (Resolve-Path -LiteralPath $LegacyRoot).Path
$destination = (Resolve-Path -LiteralPath $DestinationRoot).Path
if ($legacy -eq $destination) { throw '历史目录和目标目录不能相同。' }

# 只迁入白名单资产；现有 Rust、database、program、headless 源文件不在覆盖范围内。
$mappings = @(
    @('headless/core/decompiler', 'native/decompiler'),
    @('headless/cmake/NativeSources.cmake', 'native/cmake/NativeSources.cmake'),
    @('headless/resources/processor-pack', 'resources/processor-pack'),
    @('LICENSE', 'LICENSE'),
    @('NOTICE', 'NOTICE'),
    @('UPSTREAM_COMMIT', 'UPSTREAM_COMMIT'),
    @('licenses/zlib_License.txt', 'licenses/zlib_License.txt'),
    @('docs/design/ARM64_AUTO_INDEX_DESIGN.md', 'docs/design/ARM64_AUTO_INDEX_DESIGN.md'),
    @('docs/migration/evidence/field-schema-record-port.md', 'docs/reference/field-schema-record-port.md'),
    @('docs/migration/evidence/program-model-current-schema-port.md', 'docs/reference/program-model-current-schema-port.md'),
    @('docs/migration/evidence/node-manager-0-7-matrix.md', 'docs/reference/node-manager-0-7-matrix.md'),
    @('docs/migration/evidence/variable-key-btree-port.md', 'docs/reference/variable-key-btree-port.md')
)
$records = @()
foreach ($mapping in $mappings) {
    $source = Get-Item -LiteralPath (Join-Path $legacy $mapping[0])
    $files = if ($source.PSIsContainer) { @(Get-ChildItem -LiteralPath $source.FullName -Recurse -File) } else { @($source) }
    foreach ($file in $files) {
        $relative = if ($source.PSIsContainer) {
            Join-Path $mapping[1] $file.FullName.Substring($source.FullName.Length + 1)
        } else { $mapping[1] }
        $target = Join-Path $destination $relative
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        if (Test-Path -LiteralPath $target) {
            # 重跑时只接受相同文件，不覆盖任何新项目中的后续修改。
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $hash) {
                throw "目标已有不同内容，拒绝覆盖: $relative"
            }
        } else {
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target
        }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $hash) {
            throw "迁移后哈希不一致: $relative"
        }
        $records += [pscustomobject]@{
            source = $file.FullName.Substring($legacy.Length + 1).Replace('\', '/')
            destination = $relative.Replace('\', '/')
            sha256 = $hash.ToLowerInvariant()
            bytes = $file.Length
        }
    }
}
# 将清单输出给调用者，脚本不把临时日志散落到项目根目录。
ConvertTo-Json -InputObject @($records) -Depth 4
