# 实现与验证记录

日期：2026-10-23。环境：Windows 原生 PowerShell、Rust MSVC 工具链、MSVC 19.44。未使用 WSL。

## 已执行结果

| 检查 | 结果 |
|---|---|
| 原生 oracle 的 Release 构建与执行 | 成功，退出码 0；使用本仓库已有的 headless Release 静态库 |
| `cargo test --workspace` | 16 passed，0 failed，0 ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | 成功，无警告 |
| `cargo build --workspace --release` | 成功 |
| `cargo run -p ghidra-pcode-ir --example arm64_ir` | 成功；Packed 120 字节，恢复 3 个 Varnode、1 个操作、2 个基本块 |

Release Rust 库位于 `../target/release/libghidra_pcode_ir.rlib`。生产 crate 没有第三方依赖；C++ oracle 仅用于独立生成核对样本。

## 独立证据与证据边界

1. `opcode_numbers_match_upstream_header` 直接读取本仓库 `opcodes.hh`，核对所有已声明 opcode 数值；45、75 拒绝作为指令。
2. `opcode_flags_match_upstream_typeop_constructors` 直接读取 `typeop.cc`，核对 73 个 TypeOp 构造器设置的 opcode 标志。
3. 原生 `XmlEncode` 紧凑模式和 `PackedEncode` 生成 `LOAD`；Rust 输出与之逐字节相同。原生 `PcodeOpRaw::decode` 也成功读取该样本。
4. 原生 `PackedEncode` 生成有符号最小值、无符号最大值、布尔、字符串及扩展属性 ID；Rust 输出逐字节相同。
5. 原生 `SeqNum::encode` 生成高位地址和 uniq；Rust 输出逐字节相同。
6. Rust 图测试检查重复使用槽、同址不同 SSA 身份、修改/删除、phi、自环/平行边、CFG 入出顺序、前向 INDIRECT 引用、join、寄存器名称解析与失败回滚。
7. XML/Packed 拒绝截断、重复属性、错误关闭标签、未知实体、尾随数据和超过深度上限的输入。

第 6 项中的完整 AST 是 Rust 结构与往返验证，尚未完成真实 ARM64 ELF 函数 AST 的原生双向交叉验收。现有 4 个原生样本也不是所有空间组合、所有 opcode 形状和所有 Ghidra 程序的穷举证明。

## 原生样本 SHA-256

| 文件 | 字节数 | SHA-256 |
|---|---:|---|
| `native_load.packed` | 40 | `CE27B2A99D2F2CD1320D18035CB2229138883B5DA5AAEC215B4C348887D744D2` |
| `native_load.xml` | 146 | `4515FC958C029A088366DE291298E8826B1ECA902A3CA9DC7D84C30182EA563E` |
| `native_scalars.packed` | 37 | `5A664A36C0971DD15B421F82D7D024E57ED0BC3B62F454C8D26373EA24DEF53E` |
| `native_seqnum.packed` | 24 | `39B8F1A278C49F9BCA522200001C83E5EBC2E72C75C50CC1075CC6BA8C3DC0C8` |

生成源：`tests/native/oracle.cc`。复现命令见 `README.md`。

## “完全相同”目标仍需补齐的部分

当前完成的是 raw/SSA 基础 IR、关系维护、相关标志和交换协议。不能将本次结果标为全部 Ghidra IR/分析功能移植完成。仍需继续覆盖：

- `VarnodeBank`/`PcodeOpBank` 的完整归一化与合并行为、全部查询/变更接口及复杂地址空间行为。
- `Cover`、`HighVariable`、类型/符号/调用规格关联，以及 IR 与现有数据库模型的连接。
- 层次化 `BlockGraph` 等结构化控制流节点，及相应序列化；当前为 `BlockBasic` CFG。
- 如果目标包含“从 raw 生成优化后的 IR”，还需迁移或接入真实的 `Heritage`、`Action/Rule` 分析流程。当前 `import_raw()` 不执行这些算法。
- 对真实 ARM64 样本进行 raw、SSA、特殊引用、存储布局和序列化的原生交叉验证；当前示例为手工构造的 IR。

SLEIGH 指令解码和机器码执行本身属于 IR 的生产者/消费者，不由当前 crate 实现。所有这些边界在 README 中公开，避免后续把有限的通过项当成全部等价的结论。
