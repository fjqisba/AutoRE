# 首块局部语义优化契约

`VmSession::init_vm_context(entry_va)` 只获取入口的一个基本块。Rust 负责入口映射、生命周期和产物；worker 中的局部优化器对已展开的 Remill LLVM IR 做语义归一化。

## 输出与观察范围

`block.raw` 保留完整原始提升；`block.lifted` 是展开指令语义后的参考；`block.optimized` 是供后续 VM 初始化分析使用的块边界 IR。`VmContext.local_ir` 和 CLI 默认展示后者。

优化契约是正常完成条件下的最终 State、guest 内存及出口 PC。它要求 guest memory 与 Remill State 分离、没有并发修改或中间 State 观察者、相关访存成功。允许删除被完整覆盖的临时写入和冗余 PC 更新；不宣称保留访存故障时的原生中间状态。这些前提作为元数据输出，不能由后续流程静默丢弃。

## 优化的依据

Remill 的 flag/compare 计算 helper 在固定源码版本中是返回首参数的 identity 标记。只折叠白名单函数，源码依据为 `third_party/remill/tests/X86/Run.cpp` 和 `test_runner_lib/TestRunner.cpp`；不把未认识的外部调用假定为纯函数。

整数 guest 访存 helper 使用隔离的 memory effects，表达其不访问 State，但保留 guest 副作用。寄存器提升不再被每次 guest 访存阻断。State 字段按实际 DataLayout 逐字节处理重叠读取，不把不同宽度混用时的高位默认为零。

guest 读取转发沿实际 memory token 链逆向查找最新覆盖字节；只有所有字节都可证明时才替换。相同基址不同偏移可比较，无法证明不同基址不别名时立即停止；环境调用、原子或其他未知效果是屏障。

guest 死写消除要求原写入只有一个 token 用户，并被后续完整覆盖，期间没有剩余读观察或未知效果。部分覆盖只更新对应字节，不删除未覆盖内容。栈地址低于最终 RSP 并不意味着内容不可观察，因此不据此删除写入。

纯标志计算与回写 DAG 可以抽成有完整实现的 helper。这个步骤改善主块可读性，不等于删除其语义；统计独立列出抽取前指令数、主块指令数和含 helper 的总数。整个模块仍由 LLVM verifier 检查。

## 当前验证

回归包括常量目标与 flags 保留、部分覆盖字节拼接、未知别名阻止转发、PUSHFQ/POPFQ 后仍保留栈残留，以及刻意改坏常量后必须检出的差分反例。差分用受控 JIT 执行两份 LLVM 表示，模拟 guest 内存，比较完整 State/内存/出口；未知外部 helper 拒绝执行。

这验证优化器相对 Remill 参考 IR 的行为，不独立证明 Remill 与原机器指令等价。原有 POPFQ 权限/特殊 flags、系统状态及异常覆盖边界继续适用。
