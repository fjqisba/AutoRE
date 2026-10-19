# Il2CppDumper 构建与运行

以下 PowerShell 示例从项目根目录执行，源码默认在 `tools/Il2CppDumper/`；实际模块和 metadata 由当前目标确定。生成目录仅作示例，按项目约定换成任务子目录。

## 源码构建

先读取实际 `.csproj` 的 `TargetFrameworks`，用 `dotnet --list-sdks`、`dotnet --list-runtimes` 核对可用框架。本仓库源码含 `net6.0;net8.0`，已有 net8 运行时可选择 net8；不要把这个版本要求泛化到所有 Il2CppDumper 发行版。

```powershell
$taskDir = New-Item -ItemType Directory -Force -Path './temp_data/unity-analysis/target'
$taskPath = $taskDir.FullName
$buildDir = Join-Path $taskPath 'dumper-build'
$objDir = (Join-Path $taskPath 'dumper-obj') + [IO.Path]::DirectorySeparatorChar
dotnet build './tools/Il2CppDumper/Il2CppDumper/Il2CppDumper.csproj' `
    -c Release -f net8.0 "-p:BaseIntermediateOutputPath=$objDir" -o $buildDir
if ($LASTEXITCODE -ne 0) { throw 'Il2CppDumper 构建失败' }
```

将中间文件和构建输出放在任务目录，避免向工具源码树添加 `bin/obj`。NuGet 依赖如 Mono.Cecil 以实际项目为准。

## 配置与运行

已有发布版本时，优先将工具及其依赖复制到任务目录再配置。`config.json` 由工具自身所在目录读取，并非当前工作目录。下面仅修改独立构建产物的配置：

```powershell
$configPath = Join-Path $buildDir 'config.json'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$config.RequireAnyKey = $false
$config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $configPath -Encoding utf8
$dumpDir = New-Item -ItemType Directory -Force -Path (Join-Path $taskPath 'dump')
# modulePath 和 metadataPath 应设为已经验证、来自同一构建的输入路径。
dotnet (Join-Path $buildDir 'Il2CppDumper.dll') $modulePath $metadataPath $dumpDir.FullName `
    2>&1 | Tee-Object -FilePath (Join-Path $taskPath 'dumper.log')
```

发布版本是原生启动 EXE 时用 `& <工具路径> <模块> <metadata> <输出目录>`。本仓库命令行只识别**存在的目录**为输出目录，未创建时可能回落到工具目录。不能以退出码 0 作为充分成功证据：`Program.Main` 会捕获异常并打印；确认日志完成、所需文件非空且可解析，再确认相关类和方法存在。

常用配置 `DumpFieldOffset`、`DumpMethodOffset`、`GenerateDummyDll`、`GenerateStruct` 保持开启，保留现有无关选项。以实际 `config.json`/源码为准，旧 README 的配置名可能与当前源码不同。首次使用以日志中实际识别的版本为准，文档列出的 Unity 支持范围可能滞后。

## 方法地址提取

```powershell
python './.agents/skills/unity-il2cpp-analysis/scripts/select_methods.py' `
    './temp_data/unity-analysis/target/dump/script.json' `
    --contains 'Character' --limit 30 `
    --output './temp_data/unity-analysis/target/character-methods.json'
```

已经从 IDA 确认 PE ImageBase 时，可追加 `--pe-image-base <十六进制基址>` 生成 `pe_va`。输出保留匹配总数与截断状态；脚本只是地址候选索引，不确认函数边界或方法行为。
