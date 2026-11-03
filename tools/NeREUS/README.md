# NeREUS

Rust + LLVM + Remill 的虚拟化代码提升与恢复系统。完整架构见 [设计文档](docs/DESIGN.md)。当前已建立 Windows 原生工具链、Cargo workspace、Remill worker、首块提升及局部语义优化；VM 家族恢复、NIR 导入及 PE 回写尚未实现。

## 工具链

- Rust 1.96.0，目标 `x86_64-pc-windows-msvc`。
- LLVM 开发库 17.0.6，静态 CRT；Inkwell 0.11.0，默认只启用 x86 target。
- 语义 bitcode 使用 Clang 17.0.6；Windows 原生程序使用 VS 配套 Clang 19.1.5，兼容当前 MSVC 标准库。
- Remill 固定 revision 和 x86/x64 构建补丁见 `toolchains/versions.lock.json`。
- Visual Studio C++、Windows SDK、CMake、Ninja、Python 3.10 和 Z3。

本机路径只保存在被 Git 忽略的 `toolchains/local.json`。脚本只设置当前 PowerShell/子进程环境，不修改系统 PATH、Git 全局配置或其他项目。

## 配置与构建

在本目录的 PowerShell 7 中依次执行；首次 Bootstrap 完成前不要并行启动其他 Cargo/安装命令。初次配置时为自动发现不到的工具显式传入路径：

```powershell
./scripts/build/Configure-Local.ps1 -LLVMRoot <LLVM开发库目录> -SemanticsClang <clang.exe> -Ninja <ninja.exe> -Python <python.exe> -Z3 <z3.exe>
./scripts/build/Bootstrap.ps1 -UseProxy
./scripts/validation/Verify-Environment.ps1
```

`-UseProxy` 使用本机配置中的代理，默认配置值为 `http://127.0.0.1:7897`；不需要代理时省略。Bootstrap 拉取并检查固定 Remill revision、幂等应用构建补丁、编译依赖/语义库/worker、构建 Rust 并生成本机语义清单。已有源码 revision 不匹配时拒绝自动覆盖。

源码、补丁和 Cargo.lock 是可复现输入。`third_party/remill/` 为脚本管理的独立源码检出；`toolchains/*install/`、依赖前缀和 `temp_data/` 是本机生成物。依赖下载需要网络；增量构建可直接执行相应 CMake/Cargo 命令。

## 使用基础设施

```powershell
. ./scripts/build/Enter-Environment.ps1
cargo run --locked -p nereus-cli -- doctor
cargo run --locked -p nereus-cli -- lift-instruction --bytes 4801d8 --out temp_data/manual/add
cargo run --locked -p nereus-cli -- lift-instruction --arch x86 --pc 0x401000 --bytes 01d8 --out temp_data/manual/add32
cargo run --locked -p nereus-cli -- verify-bitcode temp_data/manual/add/instruction.bc
```

`lift-instruction` 要求恰好一条完整指令。它检查 iced 与 Remill 的指令长度，生成原始 `.bc/.ll`，再由 Rust/Inkwell 解析和验证。当前检查不构成指令行为等价证明；产物明确包含 `normalized: false` 和 `function_recovered: false`，不能当作已去虚拟化函数。

Remill worker 使用有版本、请求 ID、帧大小限制和 30 秒客户端响应超时的 JSONL 协议。它不会执行待分析代码。当前实现 `hello`、`lift-one` 和 `lift-block`，接受 `x86/amd64`；后续扩展归一化和更细能力清单时保持协议版本管理。

## 从 PE 地址提升基本块

用于后续 VM 语义分析的入口接口：

```rust
let session = VmSession::open(project_root, module_path, output_root)?;
let context = session.init_vm_context(vm_entry)?;
// context.first_block：首个原生基本块；context.local_ir：该块局部提升的 LLVM IR。
```

模块和工具环境绑定在 `VmSession`，`init_vm_context(&self, vm_entry: u64)` 的调用参数只有入口 VA。该接口仅获取并提升首个块，保存上下文，不跟随后继，也不识别/推断 VIP、VSP 等 VM 语义。

CLI 对应 `init-vm-context`（也接受别名 `init_vm_context`），stdout 直接输出这一块的 LLVM IR：

```powershell
cargo run --locked -p nereus-cli -- init_vm_context --input <PE文件> --entry 0x180914DEB --out temp_data/vm-context
```

每次初始化将首块字节、汇编、原始/局部 LLVM IR 和 `context.json` 存入输出根目录的入口地址子目录。

```powershell
cargo run --locked -p nereus-cli -- lift-pe-block --input <PE文件> --va 0x180914DEB --out temp_data/analysis/target-block
```

`--va` 按 PE 首选 ImageBase 解释，读取磁盘节区映射。当前不支持通过该命令指定运行时重定位基址或内存快照。遇到第一个控制转移即结束，包括 call；未在预算内发现终结指令时拒绝提交截断块。入口由用户提供，尚未证明它是全函数 CFG 中的天然块头，也不做全模块入边扫描。

输出 `block.asm`、`block.bin`、带地址映射的 `result.json`、完整语义库原始 `block.raw.ll/.bc`，以及仅保留依赖并展开指令语义的 `block.lifted.ll/.bc`。整理 Pass 为 `internalize,always-inline,function(sroa,mem2reg,instcombine,simplifycfg),globaldce`，不将 guest 内存常量化，也不运行默认 O3。寄存器初始值来自符号 State，入口 NEXT_PC 显式初始化为给定 VA；块末通过对应 Remill jump/call/return intrinsic 保留转移。

`init_vm_context` 的 `context.local_ir` 现在返回进一步化简的 **`block.optimized.ll`**，`context.bitcode_path` 对应 `block.optimized.bc`。原始/展开后的版本仍保留供比对。局部优化包含：

- 已确认语义的 flag/compare identity helper 折叠；未知 helper 不折叠。
- guest 内存与 Remill State 的效果分离，恢复寄存器常量传播和死写消除。
- State 重叠字段的字节级转发，保留未覆盖的高位。
- 同一基本块内、沿 memory token 链的 guest 读取转发，支持小端部分覆盖；未知别名、未知调用阻止转发。
- 删除完整覆盖且没有中间观察的 guest 写入；不会因 POP 恢复 RSP 就删除栈上残留数据。
- 常量跳转目标、上下文基址和相对槽位归一化；复杂 flags DAG 自动抽为带完整实现的 `nereus.x86.pack_flags/commit_flags` helper。

该版本是**正常完成时的块边界摘要**：前提为 guest memory 与 State 分离、普通单线程内存、相关访问无故障、无中途 State 观察者。它保留结束状态和 guest 内存，不保留故障发生时的中间 PC/寄存器轨迹；前提与计数写入 `context.json`。涉及异常或故障分析时使用 `block.raw`/`block.lifted` 版本。helper 主体仍在同一 LLVM 模块中，统计区分主块指令数和包含 helper 的总数。

worker 的 `validate-local` 操作将 reference/candidate IR 在隔离的模拟 guest 内存回调中执行，逐字节比较 State、完整测试内存和出口 PC。它不加载目标 DLL；差分通过仅验证受测输入上的优化一致性，不是原机器语义全输入证明。

这提供原生基本块到 LLVM IL 的提升；尚未实现 NIR、VM 字节码常量化或完整函数恢复。`__remill_*` 外部声明及 State 结构是该表示的接口组成部分，不是独立原生函数签名。

具体环境证据、补丁内容和当前限制见 [环境说明](docs/ENVIRONMENT.md)。
