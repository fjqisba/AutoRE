# Lumen 本机部署

把用户给出的 IDA 安装目录作为唯一必需输入，如果用户没有提供，则提示用户输入，停止下一步。

完成以下结果：

- Lumen 和 PostgreSQL 可在 Windows 本机启动、停止并保存数据；
- Lumina 仅监听 `127.0.0.1:1234`，TLS 已启用；
- HTTP 状态页无需开启监听。
- OpenLumina 插件与 IDA 版本匹配并安装到 `plugins`；
- `hexrays.crt` 位于 IDA 安装目录；
- IDA 的私有 Lumina 地址为 `127.0.0.1:1234`，用户名和密码均为 `guest`；
- TLS 握手、TCP 端口、HTTP 状态页和插件文件均经过验证。

除非出现无法自动解决的阻塞，不要再询问部署目录、端口、数据库密码或证书参数。默认部署目录为 `AutoRE/lumen`

## 边界

- 只处理 Windows 本机 `127.0.0.1` 部署，不创建防火墙规则，不开放局域网访问。
- 不把 PostgreSQL 注册成 Windows 服务，不创建计划任务或系统自启动，除非用户另行要求。
- 不把 CA 或服务器证书安装到 Windows 系统证书库。OpenLumina 从 IDA 安装目录加载 `hexrays*.crt`。
- 不上传证书、私钥、数据库或 IDA 文件。
- 不把数据库密码、PFX 密码或私钥写入公开仓库、聊天回复或命令输出。
- 不覆盖现有数据库。升级或修复时保留 `runtime\postgres-data`。
- OpenLumina 二进制必须明确兼容检测到的 IDA 版本；禁止拿“最新版”碰运气。
- 所有临时下载、源码、解压目录和一次性脚本均放在当前工作区的 `temp_data/lumen-local-deploy/` 下。成功后删除可重新下载的临时内容。

## 输入检查

1. 将用户输入规范化为绝对路径 `$IdaDir`，去除首尾引号。
2. 确认目录存在，并至少包含一种 IDA 主程序：`ida.exe`、`ida64.exe`、`idat.exe` 或 `idat64.exe`。
3. 通过主程序或 `ida.dll` 的 `VersionInfo.ProductVersion`/`FileVersion` 获取 IDA 的 `主版本.次版本`。不要仅根据目录名猜测。
4. 确认 `$IdaDir\plugins` 存在或可创建，且 IDA 根目录可写。若 IDA 位于受保护目录且写入被拒绝，先完成其他准备，再只向用户说明需要提升权限执行的复制操作。
5. 如果 IDA 正在运行，不要强制终止。请用户保存工作并关闭 IDA，然后继续安装插件和证书。

可使用以下 PowerShell 思路检查版本：

```powershell
$IdaDir = [IO.Path]::GetFullPath($UserProvidedIdaDir.Trim('"'))
$idaExe = Get-ChildItem -LiteralPath $IdaDir -File |
  Where-Object Name -in @('ida.exe', 'ida64.exe', 'idat.exe', 'idat64.exe') |
  Select-Object -First 1
$version = $idaExe.VersionInfo.ProductVersion
if (!$version) { $version = $idaExe.VersionInfo.FileVersion }
```

## 选择 OpenLumina

从 `https://api.github.com/repos/tomrus88/OpenLumina/releases` 查询官方 Release 和资产，下载到 `temp_data/lumen-local-deploy/openlumina/`。优先选择名称明确包含检测到的 IDA `主版本.次版本` 的 Windows ZIP。

已知映射可作为回退，但查询到的新官方精确匹配优先：

| IDA 版本 | OpenLumina Release | Windows 资产 |
| --- | --- | --- |
| 9.3 | `v9.3.0` | `openlumina-ida9.3.zip` |
| 9.2 | `v9.2.1` | `openlumina-ida9.2.zip` |
| 9.1 | `openlumina-v0.5` | `openlumina_win.zip` |
| 9.0 | `openlumina-v0.4` | `openlumina_win.zip` |

如果没有明确匹配：

- 检查 Release 资产内的 `ida-plugin.json`、Release 名称和说明；
- 只有元数据明确覆盖当前版本时才可安装；
- 若仍无法证明兼容，不要安装，报告“缺少匹配版本的 OpenLumina 预编译包”；
- 不要在只有 IDA 安装目录、没有匹配 IDA SDK 的情况下声称可以编译插件。

解压后只把 Windows 插件文件复制到 `$IdaDir\plugins`：

- 新版通常为 `OpenLumina64.dll` 和 `ida-plugin.json`；
- 旧版通常为 `OpenLumina.dll`；
- 不要复制 `.so` 或 `.dylib`。

若目标文件已存在且内容不同，先在 `$IdaDir\plugins\openlumina-backup-<时间戳>` 中备份，再覆盖。

## 准备 Lumen 运行环境

### 优先复用完整运行包

先检查当前工作区是否已有：

```text
bin\lumen.exe
pgsql\...\bin\postgres.exe
config.toml
start-lumen.ps1
stop-lumen.ps1
```

如果齐全，复用它并保留现有数据库。不要重新下载源码或 PostgreSQL。

### 缺少运行包时

1. 从 `https://github.com/naim94a/lumen` 获取官方源码。
2. 检查 Rust MSVC 工具链；缺失时按官方方式安装 Rust 和所需 MSVC Build Tools。
3. 执行 `cargo build --release`，复制 `target\release\lumen.exe` 到部署目录的 `bin`。
4. 下载官方 PostgreSQL Windows x86-64 binaries ZIP，解压并规范化目录，使部署目录中可以定位 `pgsql\...\bin\postgres.exe`。
6. 初始化 PostgreSQL 数据目录，创建 `lumen` 数据库，并按顺序运行 Lumen 官方 `common\migrations`。
7. 复制并调整启动/停止脚本，使脚本只依赖部署目录内的相对路径。
8. 构建完成后删除临时源码和可重新下载的压缩包，不要把 Rust 项目源码留在运行目录。

数据库应只监听 `127.0.0.1:5432`。使用随机十六进制数据库密码，避免 URL 编码问题；把密码仅写入私有 `config.toml` 和启动配置。确保这些文件不被 Git 跟踪。

## 生成本机 TLS

在部署目录创建 `tls`，生成以下文件：

```text
tls\hexrays.crt       # CA 根证书，只复制此文件给 IDA
tls\lumen.p12         # 服务器证书和私钥，只留在 Lumen 端
```

要求：

- CA 为自签名证书，`basicConstraints` 必须为 `CA:TRUE`；
- 服务器证书由该 CA 签发，`extendedKeyUsage` 包含 `serverAuth`；
- 服务器证书 SAN 至少包含 `IP:127.0.0.1` 和 `DNS:localhost`；
- PFX/P12 使用随机十六进制密码，通过进程级 `PKCSPASSWD` 提供给 Lumen；
- 私钥文件只能保留在部署目录的 `tls` 中，不复制到 IDA；
- 如果现有证书链有效、SAN 正确且剩余有效期超过 30 天，复用而不是重新生成。

可使用系统已有的 OpenSSL 3.x，或使用 PowerShell/.NET 的 `CertificateRequest` 生成证书。不要依赖某个固定的 OpenSSL 安装路径。

把 `tls\hexrays.crt` 复制为：

```text
<IDA 安装目录>\hexrays.crt
```

OpenLumina 会枚举 IDA 根目录中的 `hexrays*.crt`。证书必须为包含 `BEGIN CERTIFICATE`/`END CERTIFICATE` 的 PEM 文件。

## Lumen 配置

生成或修改 `config.toml`，保持数据库实际凭据不变，并使用本机监听：

```toml
[lumina]
server_name = "lumen-local"

[[lumina.listeners]]
bind_addr = "127.0.0.1:1234"

[lumina.listeners.tls]
server_cert = "tls/lumen.p12"

allow_deletes = false
get_history_limit = 50

[database]
connection_info = "postgres://postgres:<数据库密码>@127.0.0.1:5432/lumen"
use_tls = false

[api_server]
bind_addr = "127.0.0.1:8082"
```

注意 TOML 层级：`allow_deletes` 和 `get_history_limit` 属于 `[lumina]`，不得误放入 `[lumina.listeners.tls]`。如有歧义，保持官方示例中字段的原始层级并实际启动验证。

启动脚本必须：

1. 使用脚本自身目录解析所有路径，不依赖当前工作目录；
2. 幂等启动 PostgreSQL；
3. 只为 Lumen 子进程设置 `PKCSPASSWD`；
4. 后台启动 `bin\lumen.exe -c config.toml`；
5. 将 PID 和日志写入 `runtime`；
6. 重复执行时不启动第二份 Lumen。

停止脚本只能停止该部署目录对应的 Lumen 和 PostgreSQL 实例，不得结束其他项目或系统 PostgreSQL。

## 配置 IDA

IDA 8.1 及以上：

1. 移除 `ida.cfg`/`idauser.cfg` 中遗留的 `LUMINA_HOST`、`LUMINA_PORT`、`LUMINA_TLS`，避免无效参数警告；修改前先备份。
2. 启动 IDA，打开 **Options → General → Lumina**。
3. 选择 **Use a private server**。
4. 填写 Host `127.0.0.1`、Port `1234`、Username `guest`、Password `guest`。
5. 保持 TLS 启用并保存。

优先使用可用的 UI 自动化完成并观察设置结果。不要在 IDA 尚有未保存数据库时强制关闭或重启。如果无法可靠操作 UI，必须明确告诉用户仅剩上述 IDA 内设置，不能把文件复制成功误报为配置完成。

IDA 7.2 至 8.0：备份并编辑 `cfg\ida.cfg`：

```c
LUMINA_HOST = "127.0.0.1";
LUMINA_PORT = 1234
LUMINA_TLS = YES
```

## 验证

部署结束前逐项验证，不能只检查进程存在：

1. `pg_isready -h 127.0.0.1 -p 5432` 成功；
2. Lumen 进程的可执行文件路径属于部署目录；
3. `127.0.0.1:1234` 和 `127.0.0.1:8082` 正在监听；
4. 使用 `tls\hexrays.crt` 对 `127.0.0.1:1234` 执行 TLS 握手，证书链验证成功且服务器证书 SAN 包含 `127.0.0.1`；
6. IDA 根目录存在有效 PEM 格式的 `hexrays.crt`；
7. IDA `plugins` 中存在与版本匹配的 OpenLumina Windows DLL；
8. 可以启动 IDA 时，使用 `-z 00800000` 查看输出窗口，确认出现 OpenLumina 初始化成功信息，且没有 `can't find any hexrays*.crt`。

若验证失败，读取 `runtime` 中的 PostgreSQL 和 Lumen 日志后修复，再重新验证。端口被其他程序占用时，先确认占用者；不要擅自结束无关进程。

## 完成报告

最终只报告用户实际需要的信息：

- 部署目录；
- IDA 目录和检测到的版本；
- 安装的 OpenLumina Release/资产；
- `hexrays.crt` 的目标位置；
- 启动和停止命令；
- Lumen 地址 `127.0.0.1:1234`；
- 各验证项结果；
- 若 IDA 内设置未能自动完成，清楚列出唯一剩余操作。

不要在报告中显示数据库密码、PFX 密码或私钥内容。
