# LLMGhidra egui Workbench

Windows 原生 Rust/egui ARM64 ELF 工作台。打开文件自动建立函数、字符串、导入导出和双向引用索引；复杂函数分析按需执行。无需手动点击符号索引，也无需启动服务。

## 启动

从 `LLMGhidra/src` 执行：

```powershell
cargo build -p llmghidra-workbench --release --locked
./target/release/llmghidra-workbench.exe 'C:/Users/fjqisba/Desktop/steam-3.10.9/lib/arm64-v8a/libreactnative.so'
```

支持文件对话框、拖放和 Ctrl+O。可用 `--view strings`、`--view imports`、`--view exports` 选择加载完成后的页面。Windows MSVC、Rust 1.88+；不使用 WSL。

若无法连接 crates.io，可仅为当前构建指定镜像，无需修改全局配置：

```powershell
cargo build -p llmghidra-workbench --release --locked --config 'source.crates-io.replace-with="rsproxy"' --config 'source.rsproxy.registry="sparse+https://rsproxy.cn/index/"'
```

## 自动分析

1. 后台打开 ELF header 与 LOAD 映射，显示 Segments。
2. 分批读取 .dynsym/.symtab；无 section 时尝试 PT_DYNAMIC + HASH/GNU_HASH。同址别名合并并可搜索。
3. 读取 EH frame 入口范围、init/fini 数组、REL/RELA、Android APS2 与 RELR；保留指针槽和导入关联。
4. 分块交错扫描代码与数据。代码读取直接调用/分支，并做局部地址传播；数据识别 ASCII、UTF-8、UTF-16LE。可执行段内的只读数据不会因 PF_X 被排除。
5. 结果通过有界队列提交 SQLite WAL 缓存；界面分页读取快照，基础扫描使用独立线程，交互查询使用原有 worker pool。

首次导航优先 JNI_OnLoad，否则在元数据阶段完成后选择有来源的函数。后台结果不会持续抢走用户当前视图。候选函数名称前有问号；未知大小显示问号，FDE 范围不代表精确恢复的函数体。

## 操作

| 操作 | 行为 |
| --- | --- |
| Functions 搜索 | 匹配名称、别名或十六进制地址；每页 128 条 |
| 点击函数 | 导航到入口并按需解码当前页 |
| 双击调用/分支操作数 | 跳转直接目标 |
| X / Xrefs 按钮 | 当前地址 incoming/outgoing 引用 |
| 指令右键 | 查看该指令或目标地址的引用 |
| Strings → Xrefs | 查询包含字符串内部地址的引用范围 |
| Strings 双击地址 | 打开 Hex 原始字节 |
| Imports → Xrefs | 从导入重定位槽追踪读取与间接分派 |
| Follow refs | 沿指针、PLT/GOT 等原始引用关系继续查询 |
| F5 | 有界局部 CFG 分析，并写回共享索引 |
| Pause / Cancel | 取消在途任务，保留已提交结果 |
| Resume index | 重新读取元数据，跳过已有扫描块 checkpoint，幂等合并 |
| File → Copy analysis cache path | 复制本会话缓存路径 |
| File → Open verified analysis cache | 校验源内容哈希后重开已完成缓存 |
| Alt+Left / Alt+Right | 导航历史 |

缓存位于 `%LOCALAPPDATA%/LLMGhidra/analysis-cache/`，是可重建的分析索引，不替换已有 C++ Program 数据库。源文件只读，保持 Windows 会话文件锁。重开尚无完整指纹的缓存会拒绝，并要求重新打开 ELF；不会仅凭路径/mtime 复用。

## 结果语义与范围

- 地址均为 ELF VA，不是 file offset，也未加入 ASLR load bias。
- 引用保留类型、证据和可信级别。未知间接目标存入独立表，不计入普通目标引用。空结果不代表不存在未解析调用者。
- 全局代码扫描是 section/映射符号等范围内的线性发现；局部地址传播是候选证据，完整跨块/跨函数数据流尚未实现。
- EH frame 有常见编码解析支持；不支持的头编码、超预算表、损坏信息会形成 partial/failed 状态。无可靠代码范围时按可执行映射产生候选并告警。
- 字符串预览最多 1024 字符；跨块读取有限上下文，超过续读预算的记录保留截断标记和覆盖诊断。搜索针对已存预览，不是所有超长字符串的完整内容。
- 导入按槽位计数，一个符号可能有多个槽；导出记录包含数据符号。函数计数包含明确标注的候选。
- 不执行 ELF，不恢复运行时生成/加密字符串。没有自动全程序类型恢复或 C 伪代码输出；未连接原生 headless/P-code 反编译流程。
- 原有本地 JSONL --serve 保持原状，本次未扩展 server/MCP；GUI 的新索引查询是进程内 API。

集中验收与实测见 `AUTO_INDEX_VALIDATION.md`。此前 `VALIDATION.md` 记录的是改动前行为，不能用它描述当前自动索引。
