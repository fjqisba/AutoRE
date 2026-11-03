# NeREUS 基础环境与构建记录

日期：2026-11-03。运行平台：Windows x64，原生 MSVC ABI。本记录描述已经实际搭建的基础设施，不表示 VM 去虚拟化引擎已经实现。

## 实际工具链

| 组件 | 已选组合 |
|---|---|
| Rust / Cargo | 1.96.0，独立固定 toolchain；没有改变默认 stable 选择 |
| Rust target | `x86_64-pc-windows-msvc` |
| LLVM 开发库 | 17.0.6，Release，static，RTTI/EH OFF，静态 CRT |
| Inkwell / llvm-sys | 0.11.0 / 170.4.1，启用 LLVM 17 static 与 x86 target |
| iced-x86 | 1.22.0，具体依赖解析固定在 Cargo.lock |
| 原生程序编译器 | VS 配套 clang-cl 19.1.5 |
| 语义 bitcode 编译器 | Clang 17.0.6，配合 LLVM 17 的 llvm-link |
| MSVC / SDK | VS 2022 Professional，MSVC 14.44.35207，Windows SDK 10.0.26100.0 |
| CMake / Ninja | 4.2.1 / 1.12.1 |
| Python | 3.10.5，用于 Intel XED/mbuild |
| Z3 | 4.16.0，复用本机现有 Windows 可执行文件 |
| Remill | `56918a8c2554088e93389e97d292f4035286506c`，附构建配置补丁 |

锁定的共享版本见 `toolchains/versions.lock.json`；本机工具绝对路径见被忽略的 `toolchains/local.json`。生成的 `toolchains/semantics.manifest.json` 记录 worker、语义 bitcode、状态头文件、补丁 SHA-256 及实际依赖 commit。

选择两个 Clang 版本有明确原因：本机 VS 的新标准库要求 Clang 19 或更高版本，LLVM 17 则需要对应版本的语义 bitcode。原生 worker/Remill 库使用 Clang 19 编译并链接 LLVM 17；语义库使用 Clang 17 的 freestanding sysroot 编译，不引用 VS C++ 标准库。这不是用 LLVM 19 生成 bitcode 再交给 LLVM 17 解析。

## 已建立的目录与能力

- 独立 Cargo workspace：`nereus-core`、`nereus-x86`、`nereus-llvm-support`、`nereus-remill`、`nereus-cli`。
- Remill 源码：`third_party/remill/`，脚本管理固定 revision 的独立检出，不作为父仓库中的无版本 gitlink。
- 依赖前缀：`toolchains/remill-deps-clang19/`，含 gflags、glog、googletest、XED。
- Remill 安装：`toolchains/remill-install/`，包含库、头文件、工具及语义 bitcode。
- worker：`toolchains/bin/nereus-remill-worker.exe`。
- Rust CLI：`temp_data/cargo/x86_64-pc-windows-msvc/debug/nereus.exe`。
- 日志与验证产物：`temp_data/bootstrap/`、`temp_data/validation/`。

语义库构建生成 `x86/amd64` 的基础、AVX、AVX512 版本；上游同时生成两份带 `_sleigh` 名称的 bitcode。**生成这些文件不代表已启用 Sleigh 前端。** 当前 worker 显式接受 `x86/amd64` 基础模式；AVX/AVX512 选择、指令行为审计和完整能力矩阵仍需后续实现。

## Remill 构建补丁

补丁文件：`toolchains/patches/remill-x86-windows.patch`。

新增默认关闭的 `REMILL_X86_ONLY` 配置，启用时：

1. 只链接 x86 所需 LLVM target 库。
2. 只编译 XED x86/x64 架构实现，跳过 ARM/SPARC/PPC/Sleigh 前端和相应 BC 源码。
3. 架构工厂对没有编译的架构返回不可用，不创建伪实现。
4. 导出包和汇总头文件不要求 Sleigh 依赖。
5. 根据选定 LLVM 的 RTTI 设置匹配 Remill 编译参数。

补丁不修改 x86/x64 指令语义。x86/x64 正是本项目设计范围，因此此构建配置不缩小既定目标。后续新增架构时必须重新审查构建配置及能力，不能直接把工厂拒绝改为成功。

## 构建入口

```powershell
# 本机已经配置，直接重新构建；网络请求使用当前进程代理。
./scripts/build/Bootstrap.ps1 -UseProxy

# 将当前 PowerShell 切换到项目环境。
. ./scripts/build/Enter-Environment.ps1

# 只修改 Rust 代码时可增量构建。
cargo build --workspace --locked

# 完整基础环境检查。
./scripts/validation/Verify-Environment.ps1
```

Bootstrap 不覆盖 revision 不符的现有源码；已应用补丁通过反向检查识别。所有参数通过 PowerShell 字符串数组传递，避免小数版本和带空格路径被错误拆分。Rust 安装使用 `--no-self-update`，避免项目构建顺带更新工具链管理器。

worker 通过 LLVM 输出流写出 bitcode/IR 并检查写入错误，避免上游临时文件 rename 在 Windows 已存在目标文件时失败；同一输出目录重复运行纳入回归检查。

本机初始化时还测试过 Clang 17 编译 VS 当前标准库，会触发上游 STL 编译器版本检查，因此采用 Clang 19 原生编译路径；失败记录保留在 `temp_data/bootstrap/`，不需要重试或绕过检查。

## 验证范围与证据

实际检查包括：

- Cargo workspace 构建，固定依赖解析。
- `cargo fmt --all -- --check`。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`。
- `cargo test --workspace --locked`：两个集成测试，包含同一 worker 中的多次请求和错误后继续请求。
- 六个成功单指令用例：64 位加法、写 EAX、guest 访存、条件分支、返回，以及 32 位加法。
- iced 与 Remill 长度检查，生成 `.bc/.ll`，通过 Rust/Inkwell 重新解析及 LLVM verifier。
- 无效/截断指令、未知操作和损坏 bitcode 拒绝。
- `nereus doctor` 实际启动 worker、构造并验证 LLVM IR、检查版本及提供器文件哈希。
- Z3 对 64 位 BV 加法交换律的反例查询返回 `unsat`。
- 统一 Bootstrap 的增量重跑。

自动验证日志：`temp_data/bootstrap/verification.log`。构建重跑日志：`temp_data/bootstrap/bootstrap-replay.log`。CLI 示例结果：`temp_data/validation/cli-lift/result.json`。这些文件是本机生成证据，不作为共享源码提交。

## 当前边界

当前单指令产物仍是带完整 Remill 语义库的原始 LLVM 模块，通常包含大量未裁剪 helper。worker 没有对其运行 O3、ABI 重建或 VM 恢复。

现有成功检查证明构建和协议调用链工作，不证明机器指令行为全输入等价。NIR 导入、异常补充、数据流/内存版本、VM 适配器、CFG 不动点、平台 ABI/SEH/CET 和 PE 回写仍属于后续实施范围。

`normalized: false`、`function_recovered: false`、`nir_import_implemented: false` 和 `behavior_equivalence_verified: false` 均由当前产物明确输出。基础工具链可运行与去虚拟化能力已完成分开报告。
