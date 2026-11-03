# VM 函数分析与返回证明

`VmSession::analyze_vm_function(entry, options)` 沿可唯一证明的原生状态机后继继续提升，与 `init_vm_context` 共用 Remill、快照、不动点、VIP 及 DOT/SVG 流程。它不把 Context 初始化完成与整个函数返回混为一谈，也不把遇到任意 RET 当成调用者返回。

## 资源与检查点

`FunctionAnalysisOptions` 默认允许 512 个基本块、32768 条指令、131072 字节。CLI 提供 `analyze-vm-function --input <模块> --entry <VA> --out <目录> --max-blocks <数量> --resume-from <入口产物目录>`。资源上限始终是诊断前沿，不是语义结束。worker 单次提升允许 32768 条指令、131072 字节；Rust 与 worker JSONL 帧统一限制为 16 MiB。

检查点绑定模块 SHA-256 和入口，逐块重读原始字节校验；恢复 blocks、转移历史、VIP 和已分析语义图。只读快照事实来自带模块哈希的证据。累计路径会重新提升，传播仍要经过当前别名与 memory version 检查。最后一块尚未解析时，重新分析该前沿，不将 SMT 枚举的抽象样本当成可执行目标。检查点不执行目标 DLL，也不修改 IDA 数据库。

## 增量 IR 追加

函数模式优先从上一轮 `block.fixed-point.bc` 追加当前原生块。这个文件在局部不动点完成后、flags helper 抽取和边界命名前保存，保持可继续传播的完整 State / memory 表达式。worker 检查 prefix 唯一常量出口等于新块入口，核对目标和 State 布局；将 prefix 的出口 intrinsic 替换为原 memory token 返回，再以内联 wrapper 顺序连接 prefix 与当前块。入口 State 和 memory 不重新符号化。内部 CALL 的压栈和内部 RET 的弹栈已在 prefix 状态中保留。

没有可用 prefix、前沿未稳定或上一轮仅靠 SMT 有限目标证明时，从原生路径完整重新提升。恢复旧检查点后的第一轮也完整重做，以当前规则重新验证。逐指令 VIP 使用对应的独立 trace prefix，追加指令的 ordinal 从累计数量继续，原指令行不丢失。

每次增量追加记录 `composition.json`：prefix 路径及 SHA-256、新块地址、追加/累计原生指令数和输入模块哈希。增量轮的 `block.raw` 是 prefix 与新块的组合表示；此前原始轮与完整原生 blocks 保留用于回查，不能将它称为所有祖先未经优化的原始 IR。新增差分回归将整链从原生指令重新提升的参考 IR，与增量组合后优化的结果比较：64 组 State、guest 内存、flags 和出口 PC 均一致。

函数模式不单凭重复 `(RIP,VIP)` 宣布循环：相同语义地址可能具有不同寄存器和内存状态。当前仍按路径展开并受资源上限约束，尚无通用循环不变量、路径分叉队列或合流证明。有限双目标保留两条条件边并返回 `VJCC_FRONTIER`，不会选一路伪装成全函数恢复。

## 栈地址 MBA 的证明

不动点只保证已有传播规则稳定，未必能将所有 MBA 表达式还原为仿射地址。若纯整数地址仅依赖入口 RSP 与常量，则在 RSP=0 处计算一个候选偏移；该值只用来提出候选，不能直接替换。

worker 将表达式转换为 QF_BV，查询是否存在 64 位 RSP 使 `expression != entry_rsp + candidate_offset`。Rust 调用 Z3，只有结果为 UNSAT 才批准替换。表达式模型和候选的 SHA-256 作为证明 ID，worker 只将当前 IR 中重新生成、ID 相同的候选规范化；批准事实也参与外层不动点。

每轮 `stack-proofs/<id>.smt2` 与 `.result.txt` 保存独立查询；`optimization.progress.json` 保存候选、结果及传播过程。SAT、超时、unknown、未知输入或不支持表达式均保留原地址。纯 DAG 候选求值按 SSA 值记忆化，限制深度和节点数，避免共享子表达式被指数重复展开。

规范化之后继续使用原有逐字节 State/guest 转发与别名屏障。此规则没有给未知写入增加“不别名”特权，也不删除 VM Context、flags 或可观察的栈残留。

快照发现覆盖当前 IR 的全部常量地址 guest 读取，避免未参与末尾目标的 MBA 常量留在主 IR 中，拖累后续状态归一化。它们仍必须位于只读、文件支持的映像区域，并在具体读取点重新检查所有写入；发现一个常量地址不等于可以绕过未知写入。优化请求允许 120 秒响应，其余 worker 请求保持 30 秒；超时仍明确失败。

## 调用者 RET 的判定

当前直线路径上必须同时满足：

1. 最后一条原生指令是 RET，IR 出口为 `__remill_function_return`。
2. 最终 RSP 为入口 RSP 加 `8 + imm16`，对应弹出返回地址及可选参数清理。
3. 出口目标读取入口 `[RSP]` 的 64 位返回槽。
4. 从该读取的 memory token 回溯到入口 memory，所有写入都可证明是与该槽不重叠的入口栈相对写；未知别名、覆盖或未知 token 立即拒绝“调用者返回”证明。

满足后写 `function-analysis.json`，`status=returned`，包含 RET 地址和返回证明。这个条件是保守充分条件；不能证明时保留前沿，并非认定代码不返回。内部 CALL 压入的返回地址由栈传播解析为常量，继续跟随，不满足上述调用者终点条件。

## 本例停止位置

`(0x18131E62F, 0x18022EA1A) jmp rcx` 已解析为 `0x1810E56EE`。其计算为 `0x1DC422334 + sext64(0xA4CC33BA)`，其中 32 位立即数在 ADD 中符号扩展。中间 PUSHFQ/POPFQ 保存恢复 flags，不改变这条目标计算。此前恰好合并到第 32 块而触发固定初始化预算，不是 RCX 未知。后继首条 POP RCX 与前块 PUSH RCX 相接，应带同一 guest 栈继续分析。

继续到 `0x181538BA8` 时，旧规则因前面的 MBA 栈地址未规范化而阻断快照传播。新增证明确认 `((entry_rsp-0xB20) OR ((entry_rsp+0xF4E0) AND 0x158)) + 0x158` 恒等于 `entry_rsp-0x9C8`，结果 UNSAT；随后恢复栈转发，目标确定为 `0x18108B210`。同形回归要求成功证明，`RSP & ~0xF` 反例必须 SAT，不允许误替换。
