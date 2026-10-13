# 官方 Hex-Rays IDA MCP

已安装 [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp)，版本 `20261008.0.1`，配套 `ida-nexus 0.13.4`。当前 IDA 安装目录为 `D:\Crack Tools\IDA Professional 9.5`，使用 Python 3.14。

## 一键启动

双击本目录的 `Start-IdaMcp.cmd`，或在 PowerShell 中运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "D:\BIGAI\AutoRE\tools\ida-mcp\Start-IdaMcp.ps1"
```

默认启动本机 Streamable HTTP 服务：`http://127.0.0.1:8737/mcp`。保持窗口打开，按 `Ctrl+C` 停止。重复运行时会执行 MCP 握手，识别已有服务；若端口被其他服务占用则报错，可使用 `-Port 8738`。

启动时用 headless idalib 打开二进制或现有数据库：

```powershell
& "D:\BIGAI\AutoRE\tools\ida-mcp\Start-IdaMcp.ps1" -Database "D:\samples\sample.exe"
```

启动 IDA GUI 并打开指定文件，同时启动 MCP 服务：

```powershell
& "D:\BIGAI\AutoRE\tools\ida-mcp\Start-IdaMcp.ps1" -OpenIda -Database "D:\samples\sample.i64"
```

GUI 插件在数据库加载后自动向 IDA Nexus 注册。客户端先调用 `list_databases`，再用 `open_database` 连接对应路径。此模式不同时创建 headless worker，避免 GUI 初始化期间对同一数据库产生竞争。

如果服务已运行，再通过客户端的 `open_database` 打开文件；也可以通过 `-Port` 启动另一个服务。`-IdleTimeout` 指定释放闲置 headless 数据库租约的秒数，默认 `0` 表示不自动释放。

查看官方会话 Dashboard：

```powershell
& "D:\BIGAI\AutoRE\tools\ida-mcp\Start-IdaMcp.ps1" -Mode Dashboard
```

## Codex 接入

全局 `C:\Users\fjqisba\.codex\config.toml` 已添加名称为 `ida` 的 stdio MCP。Codex 按需启动独立 stdio 进程，不需要先运行 HTTP 服务。新聊天或重新加载 MCP 后使用；当前已经运行的聊天不会因配置文件修改自动增加工具。

等价启动命令：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "D:\BIGAI\AutoRE\tools\ida-mcp\Start-IdaMcp.ps1" -Mode Stdio -Agent codex
```

使用其他 MCP 客户端时，可以连接 HTTP 地址，也可以配置上述 stdio 命令。stdio 模式只向 stdout 输出 MCP 协议消息。

## 已安装的位置

- 官方命令：`C:\Users\fjqisba\.local\bin\ida-mcp.exe`，由 `uv tool install ida-mcp` 安装，独立工具环境位于用户 uv tools 目录。
- 官方 GUI 插件：`C:\Users\fjqisba\AppData\Roaming\Hex-Rays\IDA Pro\plugins\ida-mcp\`。
- GUI 依赖安装到 IDA 实际使用的 Python 3.14；保留原解释器配置。
- idalib 使用已有 `ida-config.json` 配置；启动脚本额外设置 `IDADIR`，确保 worker 使用指定 IDA 目录。
- 旧版第三方 `ida_mcp.py` 和 `ida_mcp` 包已按用户要求删除。

官方 hcli `0.26.3` 在安装 GUI 插件时遇到 `ambiguous plugin reference: 'ida-mcp' matches 2 plugins`。因此从官方 GitHub 源码归档部署原始 `ida_mcp_plugin.py`、`ida-plugin.json`、`LICENSE`，并安装对应官方依赖；未改写官方插件源码。hcli `plugin status` 已识别官方插件。

## 验证

- HTTP：`initialize`、`tools/list`、`list_databases` 成功。
- stdio：使用实际 PowerShell 启动命令完成同样的握手与工具调用，正常退出码为 `0`。
- headless：分析复制到 `temp_data/ida-mcp/verification/` 的系统 `where.exe`，IDA 返回 `9.5`，识别 `99` 个函数并生成 Hex-Rays 伪代码；随后释放数据库租约。
- 重复启动：识别已运行的官方 HTTP 服务并正常返回。
- GUI：启动 IDA GUI 加载验证样本，官方插件日志确认自动注册成功；MCP 发现 `backend=gui` 数据库，连接后读取 IDA 版本和函数数量成功。

验证脚本和结果在项目 `temp_data/ida-mcp/` 任务子目录，配置修改前的备份为该目录下 `backup/codex-config-before.toml`。

官方工具共六个：`open_database`、`execute_python`、`reference`、`list_databases`、`save_database`、`close_database`。具体分析通过 `reference` 查询 API，再用 `execute_python` 调用 IDAPython 或 IDA Domain API。

## 更新

更新服务：

```powershell
uv tool upgrade ida-mcp
```

GUI 插件及 GUI Python 依赖需要配套更新。通常使用官方命令：

```powershell
uvx ida-hcli plugin --no-python-environment-check install --upgrade ida-mcp@https://github.com/HexRaysSA/ida-mcp
```

若安装器仍出现同名解析错误，应从官方仓库获取匹配版本，并同步部署 GUI 插件与 `ida-nexus` 依赖。更新前关闭正在使用插件的 IDA GUI。
