# NeREUS

Rust + LLVM + Remill 的虚拟化代码提升与恢复系统。完整架构见 [设计文档](docs/DESIGN.md)。当前已建立 Windows 原生工具链、Cargo workspace、Remill worker 和单指令 bitcode 调用链；VM 家族恢复、NIR 导入及 PE 回写尚未实现。

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

Remill worker 使用有版本、请求 ID、帧大小限制和 30 秒客户端响应超时的 JSONL 协议。它不会执行待分析代码。当前实现 `hello` 和 `lift-one`，接受 `x86/amd64`；后续扩展短块、归一化和更细能力清单时保持协议版本管理。

具体环境证据、补丁内容和当前限制见 [环境说明](docs/ENVIRONMENT.md)。
