---
name: ida-pro-decomp
description: 通过IDA Pro MCP 分析已打开的 ELF、SO、PE 或固件数据库。适用于反汇编、反编译、交叉引用，以及按“先列调用/分支清单、再还原、最后双向验证”的流程还原函数逻辑；还原产物只保留语义（明文常量、原始分支），不保留密文与混淆逻辑；
---

# IDA Pro MCP

## MCP 未连接时

工具不可见、调用报连接失败，即 MCP 未启动。开关：`tools/ida-mcp/Start-IdaMcp.ps1`（相对项目根）。

必须开可见窗口启动，让用户看到服务在跑；禁止在后台作业里静默启动：

```powershell
$launcher = '<项目根>\tools\ida-mcp\Start-IdaMcp.ps1'
Start-Process powershell.exe -WindowStyle Normal -WorkingDirectory '<项目根>' -ArgumentList @(
    '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', $launcher,
    '-Port', '8737'   # 可选：-Database <文件>；-OpenIda -Database <文件>；-Port 换端口
)
```

- 窗口标题 `IDA MCP 127.0.0.1:8737`，关闭即停止；服务已在运行时重复启动会握手识别后退出，可安全重试。
- 启动后轮询端口并再次 `list_databases` 确认，成功再继续分析。
- 起不来就转述窗口里的原始错误，不要绕过 MCP。

## 标准打开和绑定流程

1. **发现数据库**：调用 `mcp__ida_pro_mcp__list_databases({})`，记录每项的 `path`、`backend`、`status` 和 `instance_id`。
2. **选择目标**：按路径末尾文件名、架构或用户指定库名匹配。例如崩溃栈同时涉及 `libil2cpp.so` 和 `libunity.so` 时，分别保存两个实例 ID。
3. **绑定执行**：后续所有 `mcp__ida_pro_mcp__execute_python`、`save_database`、`close_database` 调用传入对应的 `instance_id`。
4. **确认地址语义**：将崩溃栈中的 `pc` 减去模块加载基址得到模块 RVA；如果栈已经给出 `libfoo.so + 0x1234`，直接使用该 RVA，不要把文件偏移、虚拟地址和运行时 PC 混用。
5. **结束会话**：仅在不再需要该实例时调用 `close_database(instance_id=...)` 释放本次 MCP 租约。它不应关闭用户 GUI 中仍打开的数据库；不要为了“清理”而关闭不属于当前分析的实例。

若 MCP 正常但 `list_databases` 无目标库（先排除上节未启动）：

- 不要在本机搜索、复制或调用 `open_database` 伪造远程状态。
- 告知用户需要在远程 IDA GUI/工作器打开数据库，或请用户提供远程主机可访问的确切路径后再继续。

## 常用工具

| 工具 | 用途 | 使用要点 |
| --- | --- | --- |
| `list_databases` | 列出远程 IDA GUI/idalib 数据库 | 每次新任务先查；不要猜实例 ID |
| `reference` | 查询 `ida-domain`/IDAPython API 形状 | 在写非显然 API 前先查，例如“xrefs to address”或“decompile function” |
| `execute_python` | 在指定数据库内执行查询、反编译、反汇编、重命名和补类型 | 传 `instance_id`；优先定义 `main(db)` 并打印结构化结果 |
| `open_database` | 在远程 MCP 主机加载或附加数据库 | 仅限确认远程路径；已打开数据库不重复调用 |
| `save_database` | 保存远程数据库的重命名、注释和类型修改 | 只有用户要求或确有持久化需要时调用 |
| `close_database` | 释放本次 MCP 数据库租约 | 只关闭自己的分析实例 |

## `execute_python` 模板

以下是常见 IDAPython 查询的形状：

```python
# 目标是模块 RVA；按实际远程库的 image base 调整。
import ida_funcs
import idaapi

def main(db):
    ea = 0x74AFC
    fn = ida_funcs.get_func(ea)
    if fn is None:
        print({"address": hex(ea), "function": None})
        return
    print({
        "address": hex(ea),
        "start": hex(fn.start_ea),
        "end": hex(fn.end_ea),
        "name": idaapi.get_name(fn.start_ea),
    })
```

反汇编、反编译和交叉引用通常可按以下方式组织；不要假设一个脚本在不同 IDA 版本中所有模块都已导入：

```python
import ida_funcs
import ida_hexrays
import ida_xref
import idaapi

def main(db):
    ea = 0x74AFC
    fn = ida_funcs.get_func(ea)
    result = {"ea": hex(ea), "function": None, "callers": []}
    if fn:
        result["function"] = {
            "start": hex(fn.start_ea),
            "end": hex(fn.end_ea),
            "name": idaapi.get_name(fn.start_ea),
        }
        result["callers"] = [hex(x.frm) for x in ida_xref.XrefsTo(fn.start_ea)]
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(fn.start_ea)
            result["pseudocode"] = str(cfunc) if cfunc else None
    print(result)
```

执行约定：

- 地址、函数名、引用列表等结果尽量打印为 JSON-like 的短结构，避免直接返回超大反编译文本；需要完整伪代码时再单独请求。
- 长输出分段查询；不要因为输出截断而自行补写缺失结论。
- 远程 IDA 的路径只作为数据库标识写入报告，不要把它当成本机文件路径执行 `Get-Content`、`strings`、`objdump` 等命令。

## 函数还原流程

AI 还原函数时最容易漏东西。**先出清单，再写代码，最后回验**，三步缺一不可；
不允许"读了几段伪代码就直接写实现"。

### 1. 还原前：调用清单

- 遍历函数全部指令，收集所有 `BL`（直接调用）与 `BLR`（间接调用）目标。
- `BLR` 必须单独追：`Xn` 是哪来的（`dlsym` 动态解析、函数指针参数、表驱动），不能当成"未知"跳过。
- 每条记录：调用点地址、目标地址、目标名（`sub_XXXX` 也算）、在平坦化函数里属于哪个状态块。
- **只列导入符号不算清单**——库内 `sub_XXXX` 漏一个，还原就缺一块。

### 2. 还原前：分支清单

- 列出所有条件跳转：条件表达式、真/假分支的目标、该分支上的副作用（写指针、改全局、起线程）。
- 平坦化函数先建 `状态常量 → 块内语句 + 后继状态` 的完整转移表，再从入口状态走图；只看入口附近几块必然漏掉后半段。

### 3. 还原后：双向验证

- **调用**：清单里每个目标都要在还原代码中出现；代码里每个调用都要能指回清单的一条。对不上就补分析，不要用注释掩饰。
- **分支**：清单里每条边都要有对应分支，或明确标注"未还原/不可达"并给出证据。
- **出口**：看反汇编有没有 `RET`，不要用"看起来不返回"推断 `__noreturn`；`ADRL`/`ADR` 只是取地址，真正调用看 `BLR`。

### 4. 输出代码：写语义，不抄混淆

还原代码是给人读的，**密文和混淆逻辑一律不保留**，只能作为证据写进注释，不进代码。

