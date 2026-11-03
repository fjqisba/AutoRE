# Context 初始化状态机

入口接口保持 `VmSession::init_vm_context(vm_entry: u64) -> Result<VmContext>`。同一份 Remill State、寄存器来源、guest 内存和控制流位置共同组成状态机；模块与执行器配置由 session 绑定。

## 控制转移不等于函数调用

以入口所在执行节区为当前 VM 区域。目标仍在该区域内的原生 CALL 按 `push(return_address) + jump(target)` 继续提升，保留真实压栈副作用，不建立普通 ABI 参数假设，也不把 CALL 当作初始化完成证据。区域判断只用于解释器探索边界，不证明所有同节区代码都是同一种保护。

所有已经解析的内部边都在下一轮从入口重新提升，形成一个连续的 State/memory 转换函数。内部 CALL 没有额外的外部调用 helper；原始指令压栈仍存在。中间 RET 若能从栈求出目标，也可按机器指令的弹栈与跳转语义继续；目标不明则返回错误。

R10/R11 等寄存器只承载数据，不能固定指定某个寄存器永远是 Context 或 VIP。角色由入口来源、压栈值、目标代码重新加载和后续使用建立；相同值换寄存器不会改变角色。

## 已实现的证据阶段

- `SavingGuestState`：尚未找到同时保存 16 个入口 GPR 和 flags 的连续区域。
- `GuestStateSaved`：识别出完整 guest 保存区。这里只表示一项已完成证据，**整个初始化仍未完成**。
- `BuildingRuntimeContext`：数据流出现新的运行帧、运行时寄存器保存、元数据或解码状态写入。结果逐槽记录相对于入口 RSP 的位置与值来源。

保存区扫描不固定寄存器排列或槽位偏移；若原帧与整理后的副本同时存在，保留可识别的最终候选及证据。运行时 GPR 参数角色基于值推导，寄存器 State 偏移来自 Remill 布局元数据。

此前的 `tvm-amd64-full-gpr-flags-and-call-handoff-v1` 判据已删除：保存 16 个 GPR、flags 并压入两个值后发生 CALL，不足以证明解释器运行 Context 初始化结束。

当前 v2 只对已验证的状态阶段作正面声明；**尚未实现可普遍证明运行 Context 与派发状态均已就绪的最终判据**。因此不能重新在某个 CALL、固定块数或某次读取字节码时强行置 `complete=true`。在未获得完成证据的情况下继续探索，直到分支无法唯一求出、到达未建模外部边界或预算耗尽，然后返回异常及最新状态。这一限制会在 `state-machine.json` 中明确体现，而不返回伪完成的 `VmContext`。

## 继续与失败

每轮执行：解码一个原生基本块 → 将已确认路径重新提升至同一个转换函数 → 局部语义优化 → 收集 Context 证据与出口 → 唯一可解析内部目标继续。

未知条件的不同存活目标不选边；不能把“无法计算”写成“已证明不可达”。未解析目标返回 `BRANCH_TARGET_UNRESOLVED`，无有效执行映射返回 `BRANCH_TARGET_UNREACHABLE`。初始化期间出现区域外 CALL 返回 `EXTERNAL_CALL_DURING_INITIALIZATION`，需要明确摘要后才能继续。异常、循环及资源超限分别报错。

循环保护与增量图现使用 `(EIP, VIP)` 语义地址；尚未初始化的逐指令 VIP 显示为 `0x0`，initialized/resolved 状态单独保留。相同 handler 的不同 VIP 不合并；其他解码状态和业务状态合流仍需进一步分析，不能由当前机制宣布恢复了虚拟循环。详见 [分支语义与图](BRANCH_SEMANTICS.md)。

## 产物与观察模型

每轮都将最新 `block.raw`、`block.lifted`、`block.optimized` 及原生汇编保存在入口目录，不会在失败时留下旧的成功结果作为当前结果。`rounds/` 保留逐轮产物，`initialization.progress.json` 保留证据变迁，`state-machine.json` 保存原生块、转移类型、当前角色与运行 Context 写入。失败另写 `initialization.error.json`，并将 `context.json` 标记为 failed。

正常完成状态的优化契约仍然要求 guest memory 与 State 分离、普通无并发内存、相关访存无故障、无中途 State 观察。快照常量传播还要求相关只读映像等于所给文件快照、入口栈与映像分离，事实及来源独立记录。未规定 flags 的 helper 表达未知值而不会改写 GPR 或 guest 内存；它不会被当作零。原始故障/权限语义与动态行为证明仍需独立验证。
