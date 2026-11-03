# 首块局部语义优化契约

`VmSession::lift_entry_block(entry_va)` 提升入口的一块；`init_vm_context(entry_va)` 则按 [完成判定与分支规则](VM_CONTEXT_INITIALIZATION.md) 增量合并初始化链。Rust 负责入口映射、生命周期和产物；worker 中的局部优化器对已展开的 Remill LLVM IR 做语义归一化。

## 输出与观察范围

`block.raw` 保留完整原始提升；`block.lifted` 是展开指令语义后的参考；`block.optimized` 是供后续 VM 初始化分析使用的块边界 IR。`VmContext.local_ir` 和 CLI 默认展示后者。

优化契约是正常完成条件下的最终 State、guest 内存及出口 PC。它要求 guest memory 与 Remill State 分离、没有并发修改或中间 State 观察者、相关访存成功。允许删除被完整覆盖的临时写入和冗余 PC 更新；不宣称保留访存故障时的原生中间状态。这些前提作为元数据输出，不能由后续流程静默丢弃。

## 优化的依据

Remill 的 flag/compare 计算 helper 在固定源码版本中是返回首参数的 identity 标记。只折叠白名单函数，源码依据为 `third_party/remill/tests/X86/Run.cpp` 和 `test_runner_lib/TestRunner.cpp`；不把未认识的外部调用假定为纯函数。

整数 guest 访存 helper 使用隔离的 memory effects，表达其不访问 State，但保留 guest 副作用。寄存器提升不再被每次 guest 访存阻断。State 字段按实际 DataLayout 逐字节处理重叠读取，不把不同宽度混用时的高位默认为零。

guest 读取转发沿实际 memory token 链逆向查找最新覆盖字节；只有所有字节都可证明时才替换。相同基址不同偏移可比较，无法证明不同基址不别名时立即停止；环境调用、原子或其他未知效果是屏障。

guest 死写消除要求原写入只有一个 token 用户，并被后续完整覆盖，期间没有剩余读观察或未知效果。部分覆盖只更新对应字节，不删除未覆盖内容。栈地址低于最终 RSP 并不意味着内容不可观察，因此不据此删除写入。

纯标志计算与回写 DAG 可以抽成有完整实现的 helper。这个步骤改善主块可读性，不等于删除其语义；统计独立列出抽取前指令数、主块指令数和含 helper 的总数。整个模块仍由 LLVM verifier 检查。

## IR / 状态驱动的不动点

局部优化采用两层不动点。这里的“状态”是当前合并路径的数据流与边界分析证据，不是执行一次目标 DLL，也不是证明所有路径的循环合流已经收敛。

worker 每轮依次执行 State 字节传播、LLVM 化简、guest 读取转发、只读快照传播、完整覆盖死写消除和 LLVM 再化简。比较轮前/轮后的完整 LLVM 模块文本与边界状态：Context 初始化证据、出口目标位向量模型、Context 读依赖。**只有 IR 与状态均不变才收敛**。指令数和自定义 pass 命中数只用于诊断；相同指令数可能具有不同表达式，即使自定义 pass 没命中，LLVM 自身也可能继续改变 IR。

Rust 外层从最终 IR 暴露的目标/Context 依赖补充快照，再使用保留的 `block.lifted.bc` 和累计事实重新求值。比较完整输出 IR、初始化/分支/Context 依赖/逐指令 VIP 证据，以及完整事实映射。只有全部不变且本轮没有新事实等待消费才结束。快照集合字节数不变不能单独作为结束条件。保留未裁剪的输入可以避免跨轮丢失数据依赖；每次快照替换仍需重新通过当前 memory version 与别名屏障检查。

worker 返回 `converged`、`stop_reason`、`iteration_history`。每轮记录 `ir_changed`、`state_changed`、IR/状态 SHA-256 和 pass 计数；真正的相邻稳定判断采用完整表示相等，SHA-256 用于日志及振荡检测。Rust 将外层变化轨迹和最后一次 worker 报告保存为 `optimization.progress.json`。helper 抽取与边界命名在 worker 内层收敛后执行，Rust 还会比较这个最终交付表示，避免将格式化过程的统计混入不动点条件。

资源上限与不动点分开：worker 默认最多 256 轮，可用 `iteration_budget` 在 1–4096 范围内调整；Rust 外层最多 256 轮。相邻表示不变为 `fixed-point`，重复较早表示为 `optimization-cycle`，未稳定便用尽资源为 `iteration-budget-exhausted`。最后允许的一轮恰好稳定仍算收敛。worker 为便于诊断可以输出 `converged=false` 的候选 IR；Rust 必须拒绝将它送入分支分类/后继合并，写入诊断后抛出 `OPTIMIZATION_NOT_CONVERGED`。因此未充分传播的间接目标不会被误当成真实多目标语义。

此循环不扩大优化权限：最终 State、guest 内存与出口 PC 仍为观察输出；未知调用、未知别名、有可能覆盖快照的写入继续阻止传播。flags helper 具有真实实现，Context 写入不会因为看似临时栈操作而被删除。原始 IR、展开参考 IR、快照前提和逐指令 `(RIP, VIP)` 图仍保留。

## 当前验证

回归包括常量目标与 flags 保留、部分覆盖字节拼接、未知别名阻止转发、PUSHFQ/POPFQ 后仍保留栈残留，以及刻意改坏常量后必须检出的差分反例。差分用受控 JIT 执行两份 LLVM 表示，模拟 guest 内存，比较完整 State/内存/出口；未知外部 helper 拒绝执行。

这验证优化器相对 Remill 参考 IR 的行为，不独立证明 Remill 与原机器指令等价。原有 POPFQ 权限/特殊 flags、系统状态及异常覆盖边界继续适用。

不动点回归还包括 24 层只读指针链：外层经过 26 轮后稳定，证明不再受旧的 16 轮退出限制。`scripts/analysis/verify_fixed_point_1815f05be.py` 使用已保存的真实合并链和 93 项快照事实重现 `(0x1815F05BE, 0x18022E986)`：默认第 10 轮稳定，出口为 `0x181562C26`；限制为 8 轮必须标记未收敛，恰好给 10 轮则必须标记已收敛。该脚本只重做局部优化，不扩展后继。

另一项 12 层局部快照依赖回归从一开始就提供全部事实，验证 worker 自身仍需超过 8 轮传播，并检查预算耗尽、最终稳定及恰好最后一轮稳定的三个结果。全工作区 28 项测试与 `cargo clippy --workspace --all-targets --locked -- -D warnings` 通过。

真实合并链的参考入口 IR 有 8283 条指令；收敛后抽取 flags helper 前为 231 条，主入口 208 条，连同 helper 为 254 条。初始化检查仍识别 16 个保存的 GPR、9 项运行 Context 写入，`complete=false`。这些统计表明结构与证据仍在；语义保证仍来自上面的优化观察契约和受测输入差分，不将压缩率视作等价证明。

入口 `0x180914DEB` 的完整重跑产物保存在 `temp_data/fixed-point/ace/180914deb/`。状态机已越过原阻塞点并合并 32 个原生块，随后因独立的初始化合并上限报 `INITIALIZATION_BUDGET_EXCEEDED`，待分析目标为 `0x1810E56EE`。这个结果不表示局部优化未收敛，也不表示 VM Context 初始化已完成。逐指令图保持 DOT/SVG，未生成或阅读 PNG。
