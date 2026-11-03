# 自动基础索引实现与验收记录

日期：2026-10-23。平台：Windows 原生 PowerShell / MSVC，AMD Ryzen 7 9700X，16 个逻辑处理器。后台扫描最多 6 worker，原有交互池最多 8 worker。未使用 WSL，未扩展 server/MCP。

## 实际交付

可执行文件：`../target/release/llmghidra-workbench.exe`。

- 打开 ELF 自动创建索引会话，分批发现函数；不再要求用户手动 Index symbols。
- 动态/静态函数符号、别名、EH frame 范围、初始化入口、直接 BL 目标及重定位代码指针合并为入口记录。弱证据保留 candidate。
- 首次导航优先 `JNI_OnLoad`，不存在时选有来源函数；不把 RX LOAD 起点当作已确认代码入口。
- 直接控制流和局部数据引用形成双向索引，记录地址形成、读写、指针槽、导入分派等关系。未知间接目标独立保存，不伪造目标 0 或自引用。
- ASCII、UTF-8、UTF-16LE 字符串自动扫描。section 名称和类型用于排除 ELF 元数据、异常展开/异常处理表；PF_X 不会排除其中的真实只读数据。
- Functions、Strings、Imports、Exports、Xrefs 分页展示；函数搜索包含别名；字符串引用支持范围查询；指令旁显示目标名称或字符串预览。
- Xrefs 支持 incoming/outgoing、引用点跳转和继续追踪目标。函数归属提示明确为范围证据，未恢复边界时不伪装为准确归属。
- 基础扫描独立于交互池，代码/字符串任务交错，任务队列 32、结果队列 8，有界内存与事务批次。暂停保留结果，同会话 Resume 跳过已提交扫描块。
- SQLite WAL 保存可重建分析索引。File 菜单可复制路径、显式重开已完成缓存；重开先做完整 SHA-256 校验。
- F5 局部分析结果写回同一索引。既有服务协议保持原状，新 GUI 查询不依赖服务。

## 源码位置

| 文件 | 职责 |
| --- | --- |
| `../analysis-core/src/index/mod.rs` | 索引会话、状态、后台调度、暂停续跑、完整指纹、局部结果合并 |
| `../analysis-core/src/index/metadata.rs` | sections/dynamic、符号、GNU hash、unwind、重定位、init/fini |
| `../analysis-core/src/index/scan.rs` | 分块指令扫描、局部地址传播、字符串扫描 |
| `../analysis-core/src/index/store.rs` | 事务、稳定入口/别名、双向引用、分页查询、缓存 |
| `src/ui/index_view.rs` | 函数、字符串、引用、导入导出页面和异步查询 |
| `src/ui.rs` | 自动启动索引、导航、取消、状态和反汇编注释 |
| `../analysis-core/tests/baseline.rs` | 自动分析闭环与跨块回归检查 |
| `../analysis-core/examples/baseline.rs` | 真实 ELF 离线测量入口，不启动服务 |

## 构建与集中验证

以下均通过：

- Windows release 工作台构建。
- `cargo clippy -p llmghidra-analysis -p llmghidra-workbench --all-targets -- -D warnings`。
- `cargo test -p llmghidra-analysis --release`：原有 8 项 + 新增 1 项集成检查通过。
- 新增检查涵盖 entry=0 自动函数发现、直接调用 incoming/outgoing 对称、ADRP+ADD 地址引用、LDR 读取、ASCII/UTF-16、两种字符串跨 256 KiB 块边界、续跑无重复计数，以及已完成缓存校验重开。
- 真实样本 release 索引执行成功；实际启动工作台，通过应用 framebuffer 截图检查函数页与 Strings 页。未声称用 UI 自动化逐个点击验证所有按钮。

本机 crates.io 无法连接，构建命令临时追加 rsproxy source 配置；没有修改用户全局 Cargo 配置。依赖下载完成后验证使用 `--locked --offline`。

## 指定真实样本的最后实测

文件：`C:/Users/fjqisba/Desktop/steam-3.10.9/lib/arm64-v8a/libreactnative.so`。

SHA-256：`28AA21C60DE143AE45DF4223666E048EEFD740FB33DA6A44F91DEA5C68207773`。

| 指标 | 结果 |
| --- | ---: |
| 首次观察到函数结果 | 41.48 ms |
| 基础索引 + 完整文件指纹 | 1,735 ms |
| 函数入口记录 | 16,035 |
| 其中候选入口 | 3,585 |
| 其余有元数据证据的入口 | 12,450 |
| 字符串 | 4,721 |
| 已索引目标引用事实 | 220,398 |
| 单独记录的未解析间接站点 | 12,162 |
| 导入槽记录 | 3,122 |
| 导出符号记录（含数据） | 10,849 |
| 代码/业务数据扫描范围 | 3,514,748 bytes |
| JNI 入口 | `0x383f84`，主名 `JNI_OnLoad`，保留 Weak 别名 |

首批时间是同引擎离线入口每 10 ms 轮询观测值，不是 GUI 从进程启动到首帧的时间。该次没有清空操作系统缓存，是一次测量；不能当作冷启动/P95 或任意大文件性能承诺。两次并行运行 GUI 截图时各自索引约 2.18–2.20 秒，仅供实际运行证据。

“有元数据证据”不表示边界已完整恢复，3,585 个 candidate 也不能计为已确认独立函数。引用事实包含控制流、数据与指针槽等类别，不是调用边总数。JNI_OnLoad 没有当前索引中的 incoming 引用并不意外，它可由动态加载器按导出符号调用；不能据此断言运行时无人调用。

在截图检查中发现过异常处理表产生的 UTF-16 噪声，最终实现已排除相应已命名元数据区域并收紧编码候选条件；因此中途较大的字符串计数不作为最终结果。

截图：

- `../../temp_data/egui-workbench/acceptance/auto-index-final.png`：自动定位 JNI_OnLoad，反汇编旁显示 `jni_lib_merge` 与日志字符串引用。
- `../../temp_data/egui-workbench/acceptance/auto-strings.png`：真实业务文本、字符串地址和 Xrefs 入口。

## 与目标设计的差异及剩余工作

设计文件仍是完整目标，不能宣称本次已经完成其中所有条目。

1. **存储整合**：当前是独立 SQLite 可重建缓存，未接入 C++ Program/ReferenceManager/FunctionManager 的 FFI。原生类型/签名数据库未被替换。
2. **数据流精度**：局部常量传播尚未实现全局基本块前驱汇合、跨块失效重算、完整跳转表和间接调用恢复。section 线性扫描的代码身份也不是完整递归 CFG 证明；结果保留证据级别。
3. **复杂格式覆盖**：PT_DYNAMIC、GNU_HASH、APS2、RELR 等已有实现，但本次新增集成检查不覆盖所有编码变体，真实样本主要覆盖普通 RELA/unwind；无 section 极端文件和恶意编码仍需独立语料验收。
4. **长字符串**：预览上限 1024 字符，跨块续读上下文有限，超长 extent 标记 partial 并诊断。全文检索目前针对存储预览，未做完整文本倒排索引；UTF-16 候选过滤可能漏掉不符合文本分布条件的内容。
5. **引用细节**：当前数据引用没有完整保存每条指令的 operand index/访问宽度；字符串内部查询按地址范围匹配，未全面验证每个内部目标是否为合法 Unicode 字符边界。
6. **缓存与会话**：支持同会话暂停续跑和已完成缓存显式重开，未做自动缓存查找、后台内容身份匹配、缓存清理策略；没有完成指纹的中断缓存不能跨进程直接恢复。
7. **调度与指标**：当前独立交互池 + 有界交错扫描满足实际浏览路径，未实现设计中的完整加权优先级调度与精细分阶段 coverage。没有真实大型 ELF 冷缓存/P95/峰值 RSS 验收，不用稀疏填充文件替代。
8. **反编译**：本次交付基础发现与浏览闭环，没有新增 C 伪代码输出或 Rust P-code / C++ headless 连接。

既有 `AGENTS.md` 未修改；构建、截图、测试数据均位于子目录或应用专用缓存目录。
