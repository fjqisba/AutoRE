# LLMGhidra1 历史资产复用与 Rust 项目归档

日期：2026-10-23。目标：让当前 Rust 项目拥有值得复用且可追溯的历史资产，修复搬走旧树后失效的依赖，并独立纳入 Git。没有将目标改成旧 C++/Qt 应用，也没有扩大到 server/MCP 开发。

## 选择结果

| 历史资产 | 处理 | 用途及边界 |
| --- | --- | --- |
| `headless/core/decompiler` | 原样迁入 `native/decompiler`，203 文件 | Decompiler 算法、SLEIGH、zlib；作为 Rust 移植参考和原生协议 oracle |
| `headless/cmake/NativeSources.cmake` | 迁入 `native/cmake` 后调整相对路径 | 保留原明确源清单、共享源去重和不包含 Java printer 的构建边界 |
| `headless/resources/processor-pack` | 原样迁入 `resources/processor-pack`，23 文件 | AARCH64 三个 SLA、源语言、处理器/编译器规格；保留 ldefs 所需变体 |
| `docs/design/ARM64_AUTO_INDEX_DESIGN.md` | 原样迁入相同相对位置 | 与当前 Rust 自动索引实现关联的设计依据；旧问题描述属于设计时背景 |
| Field/Schema/Record、ProgramDB schema、NodeManager、variable-key B-tree 资料 | 4 篇迁入 `docs/reference` | 后续 Rust 数据库迁移的语义依据，历史测试结论不升级为当前结果 |
| LICENSE、NOTICE、UPSTREAM_COMMIT、zlib License | 原样迁入 | 保留上游版本锚点、作者声明与独立第三方许可证 |
| 已有 `src/database` | 保留现状，不重复复制 | 94 文件与旧 headless 副本一致；避免双份数据库源继续分叉 |
| 已有 `src/program`、`src/headless` | 保留现状，不覆盖 | 与旧 headless 存在差异；此次没有把旧实现当作较新版本强行覆盖 |
| 旧 headless session / ELF loader / Qt GUI / CLI | 留在历史目录 | 当前 ELF/索引/UI 归 Rust 主线；旧 session 与旧 providers/Program API 配套，不能只复制缺失文件就声称接通 |
| Ghidra Java 源、Gradle、全架构树、旧全量迁移账本 | 留在历史目录 | 不作为当前 Rust 应用构建或运行依赖 |
| `build`、`out`、`.gradle`、旧样本/数据库、临时日志 | 不迁移 | 不将机器缓存与分析对象纳入源码版本 |

本次白名单导入共 236 文件，10,947,993 bytes。完整来源、目标、导入时哈希和大小见 [legacy-assets.json](legacy-assets.json)。其中 `NativeSources.cmake` 随后只调整源码目录引用，清单保留其导入时原始哈希，其余导入文件保持字节一致。新写的构建入口、说明和脚本不计入 236。

## 实际修复

1. P-code 两处 `include_str!` 从已经不存在的 `headless/core/decompiler/cpp` 改到 `native/decompiler/cpp`；opcode/TypeOp 校验再次拥有真实源码基准。
2. `tests/native/CMakeLists.txt` 通过 `add_subdirectory` 构建本地原生目标，不再引用旧 `out/headless-msvc/Release/*.lib`。
3. 新增独立 `native/CMakeLists.txt`：Decompiler、SLEIGH、共享原生库、zlib，以及可选 SLEIGH 编译器。Cargo 成员仍只有原来的三个 Rust crate。
4. 新增项目总览与架构图，明确 SQLite 分析索引、Rust IR、C++ 数据库和原生算法参考之间的实际连接状态。
5. 外层 `.gitignore` 仅增加历史目录 `/LLMGhidra1/`；项目内规则排除 target/out/build、缓存、二进制和临时任务。保留 Cargo.lock、SLA 及 P-code fixtures。
6. `.gitattributes` 为原生语言二进制、协议样本和带哈希的导入资产关闭换行转换，避免 Windows checkout 破坏字节证据。

导入工具位于 `tools/migration/import-legacy.ps1`，仅用于恢复这批白名单原始资产，不参与正常构建。目标文件已存在且内容不同时会拒绝覆盖；本次调整过的 CMake 清单因此也会受到保护。它不是自动合并或同步旧项目的工具。

## 能力边界

当前生产路径仍为 Rust ELF/ARM64 解码、并发基础索引和 egui。P-code crate 的表示/协议与原生参考工具不等于已经实现 SLEIGH → SSA → 优化 → C 伪代码的 Rust 全流程。此次不新增 FFI，也不把 C++ 数据库伪装成 Rust 存储实现。

上游标记是历史目录提供的 `Ghidra_12.1.3_build` / `8b4c91d4d5bd1549622bfbade0df199585b98365`；这是来源锚点，不意味着历史快照内所有文件均未经修改。本次记录的是实际迁入字节的哈希，没有通过网络重新认证历史工作树。

## 集中验证

迁移及路径调整完成后，在 Windows 原生 PowerShell、Cargo 1.96.0、CMake 4.2.1、MSVC 19.44 x64 下集中验证，未使用 WSL。

| 项目 | 本次结果 |
| --- | --- |
| Rust release 工作台构建 | `cargo build -p llmghidra-workbench --release --locked --offline` 通过 |
| Rust workspace 检查 | `cargo test --workspace --release --locked --offline` 通过：16 项 IR + 8 项 analysis + 1 项自动索引，共 25 项 |
| 可选原生工程 | 从 `src/pcode-ir/tests/native` 配置，开启 SLEIGH 编译器；MSVC Release 构建全部目标通过 |
| 原生 oracle 运行 | 输出到忽略的 `out/native-oracle/generated-fixtures`，4 个结果与已提交 fixtures SHA-256 完全相同 |
| 导入资产完整性 | 除明确调整的 CMake 清单外，235 个文件重新核验 SHA-256 一致 |
| AARCH64 ldefs 资源引用 | 两份 ldefs 共 23 次 SLA / pspec / cspec 引用均指向存在文件 |
| Git 规则与范围 | target/out/历史目录正确忽略；SLA、fixtures、Cargo.lock 正常纳入；暂存路径仅项目目录和外层 `.gitignore` |

Cargo 使用本机已有 rsproxy 依赖缓存，在命令中临时追加 `--config 'source.crates-io.replace-with="rsproxy"' --config 'source.rsproxy.registry="sparse+https://rsproxy.cn/index/"'`；没有修改全局配置。原生 oracle 构建命令（从项目目录执行）：

```powershell
cmake -S src/pcode-ir/tests/native -B out/native-oracle -G 'Visual Studio 17 2022' -A x64 -DLLMGHIDRA_BUILD_SLEIGH_COMPILER=ON
cmake --build out/native-oracle --config Release --parallel 8
./out/native-oracle/Release/pcode_ir_oracle.exe ./out/native-oracle/generated-fixtures
```

原生历史源码仍有 MSVC 的 class/struct 声明、未使用变量、数值转换等警告；此次没有为消除警告改写上游算法。本次未重新测量真实 SO 性能、未进行 GUI 视觉验收、未构建现有 C++ database/Program/providers，也未验证整套反编译语义等价。历史验收文档只保留原记录，不作为本次结果。

## Git 范围

此次提交范围为 `LLMGhidra/` 和外层 `.gitignore`，包括当前此前尚未跟踪的 Rust workspace 及其既有 C++ 参考代码。`AGENTS.md`、其他项目/工具的已有修改和仓库其他未跟踪目录均不纳入提交。历史目录仅忽略，未删除，可继续从本机查阅。
