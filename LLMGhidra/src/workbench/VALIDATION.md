# egui / ELF 按需分析验收记录

日期：2026-10-23（北京时间）。平台：Windows 原生 PowerShell、Rust 1.96.0、MSVC，未使用 WSL。

## 已验证

- `cargo build -p llmghidra-workbench --release --locked` 成功，生成原生 EXE。
- `cargo clippy -p llmghidra-analysis -p llmghidra-workbench --all-targets -- -D warnings` 通过。
- `cargo test -p llmghidra-analysis --release`：8 项通过，0 失败。覆盖按需读取、大小端 ELF32/64、文件/BSS 映射、损坏输入、有界 CFG、取消、缓存、无 section header、AI 分页接口。
- `scripts/check-protocol.ps1`：向真实 Release EXE 一次提交 9 个 JSONL 请求，核对 metadata、segments、函数分页、虚拟内存读取、反汇编、CFG、预算停止、无效 VA 和第二个函数分析。9 项全部通过，响应以 id 关联。
- 实际运行 egui 窗口，退出码 0，stderr 为空；通过 eframe framebuffer 截图检查浅色布局、函数侧栏、字节/地址/指令显示和输出窗口。

截图：`../../temp_data/egui-workbench/acceptance/workbench.png`。

## 文件尺寸与初始化读取量

使用 Release `analysis-core/examples/measure.rs`，每个文件一次调用，操作系统缓存没有清空。测量函数内不包含 GUI 初始化、字体加载或进程启动。

| 输入 | 文件大小 | 头部打开 | 头部读取量 | 当前页解码 | 局部分析 | 含符号索引后的累计读取量 |
|---|---:|---:|---:|---:|---:|---:|
| 合成 AArch64 ELF | 13,312 字节 | 0.0561 ms | 192 字节 | 0.5851 ms / 64 条 | 0.0444 ms / 7 条、3 块 | 4,571 字节 |
| 相同头部/代码的稀疏 ELF | 8,589,934,592 字节（8 GiB） | 0.0577 ms | 192 字节 | 0.2495 ms / 64 条 | 0.0284 ms / 7 条、3 块 | 4,571 字节 |
| 仓库既有 `sample.so` | 3,152 字节 | 0.3285 ms | 528 字节 | 0.2329 ms / 44 条 | 0.0148 ms / 2 条、1 块 | 5,736 字节 |

8 GiB 样本的数据 PT_LOAD 覆盖文件剩余部分；程序没有通过绕开该段映射来伪造小文件。两个合成样本的 header 都为 2 个 program headers：16 字节 ident + 64 字节 ELF header + 2 × 56 字节 program header = 192 字节。GUI 对同一合成小文件实测头部打开约 0.16 ms，随后只为当前反汇编页读取一个代码页。

这些数字证明的是**初始化不按文件总长度扫描或分配**。稀疏 ELF 的实际数据量很少，不能代表 8 GiB 真实代码、冷磁盘、大型复杂函数、网络盘或全部函数识别耗时；也没有与 IDA 在相同样本和相同任务上做基准对照。

## 资源边界与可观察行为

- 默认 2–8 个工作线程；队列长度为线程数 × 4，满时报告背压。
- 文件页缓存：64 × 4 KiB = 256 KiB，和文件总大小无关。
- 符号表显式索引，缓存并合并并发请求；不会在首次打开时进行索引。
- 函数/反汇编列表采用虚拟滚动；分析基本块视图也仅渲染可见卡片。
- 默认请求预算：4096 条指令 / 750 ms / 1 MiB 地址跨度；达到预算返回部分结果和原因。
- 没有全程序解码任务，没有隐藏的“继续扫描整文件”后台队列。
- 直接调用目标作为有来源的候选；间接跳转、缺失符号等情况明确表示未知。

## 范围限制

界面具备请求分析的完整入口，结果为 ARM64 指令与局部 CFG。目前没有 C 伪代码输出、P-code/headless 反编译连接、数据库持久化或全程序 xref。ELF32 可读取元数据，指令引擎仅支持 AArch64。当前无 section headers 的动态符号恢复尚未实现，但按 PT_LOAD VA 浏览、读取和分析不依赖它。

这不是像素级 IDA 复刻验收；本次验收的是用户要求的基本 egui 界面、ELF/SEGMENT、按需多线程分析与 AI 请求路径。
