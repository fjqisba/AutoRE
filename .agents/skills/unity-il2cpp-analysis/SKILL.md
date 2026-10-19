---
name: unity-il2cpp-analysis
description: 使用 Il2CppDumper 分析 Unity IL2CPP 原生模块与 global-metadata.dat，恢复类、字段偏移和方法地址，并关联 Unity 角色、皮肤、Prefab 与动画资源。适用于 Unity 编译程序的代码和资源分析；真实方法行为交由关联的 IDA 技能核对。
metadata:
  short-description: 恢复 Unity IL2CPP 类型、地址并关联资源
---

# Unity IL2CPP 分析

Il2CppDumper 提供类型和地址地图，不还原真实 C# 方法体。用它缩小问题范围；需要解释算法、边界条件、移动逻辑或副作用时，再用 [IDA 反编译分析技能](../ida-decomp-analysis/SKILL.md) 核对机器码。需要展示角色外观、移动素材时，沿序列化引用定位原始 Unity 资源并交付可查看的图像或动画证据。

## 确认后端和输入

- Windows 常见组合是 `GameAssembly.dll` 与 `<游戏名>_Data/il2cpp_data/Metadata/global-metadata.dat`。游戏主 EXE 往往只负责调用 UnityPlayer，不能把它当成玩法代码模块。
- Android 常见组合是对应架构的 `libil2cpp.so` 与 metadata；其他平台按实际包结构定位原生模块。模块、metadata 和资源应来自同一构建，记录平台、架构、Unity 版本及输入指纹以便复核。
- 若只有正常的 `Managed/Assembly-CSharp.dll` 而没有 IL2CPP 模块，先判断是否 Mono 后端；用 .NET 反编译工具分析实际程序集，不套用 IL2CPP 流程。
- 优先复用已有有效 dump。新任务需要本地工具时检查项目 `tools/Il2CppDumper/`，位置不同时按用户提供路径或文件搜索结果确定，不自动重装工具或修改全局配置。

## 获取可复核的恢复结果

1. 检查 Il2CppDumper 可执行产物、`config.json`、目标框架及运行时；仅有源码时按 [运行参考](references/dumper-workflow.md) 构建到任务子目录。
2. 显式提供原生模块、metadata 和**已经存在的输出目录**。自动运行时在任务独立工具副本的配置中设置 `RequireAnyKey=false`，避免交互等待。
3. 保存日志中的 metadata/IL2CPP 版本、注册结构定位和错误。该工具可能捕获异常仍返回退出码 0，因此还要检查日志与必需产物，不能仅凭退出码判定成功。
4. 首先检查 `dump.cs` 的相关类及字段、`script.json` 的候选方法；大型文件用 `rg` 或有界脚本检索，避免把全量 dump 放进上下文。

| 产物 | 可用证据 | 不能据此断言 |
|---|---|---|
| `dump.cs` | 类层级、字段偏移、属性、签名、方法 RVA 等 | 空方法体就是没有逻辑，或它是原始 C# 源码 |
| `DummyDll/` | 恢复的程序集、类型布局，供资源解析器生成 type tree | ILSpy/dnSpy 展示的占位方法体是真实实现 |
| `script.json` | 方法名、签名、地址映射和元数据索引 | 名称足以证明行为，或地址一定是运行时 VA |
| `il2cpp.h` | 原生对象字段布局和候选类型 | 可以无条件批量应用到 IDA 数据库 |
| `stringliteral.json` | 字符串与地址线索 | 出现某字符串就是该功能已执行 |

若解析失败，先核对文件配对、架构、格式和工具版本支持。不要根据 Unity 版本号随意设置 `ForceVersion`；该选项影响原生二进制解析器，不会覆盖 metadata header 版本。遇到加密、混淆或内存 dump 地址重定向，记录明确限制；运行时 dump/解密是另一项分析工作，不能用空输出冒充成功。

## 与 IDA 技能协作

- Il2CppDumper → IDA：提供模块及指纹、候选方法名/签名、原始地址值和地址语义、相关字段偏移。Windows PE 的本仓库 `ScriptMethod.Address` 是 RVA；从 IDA 查询当前数据库基址后计算 `VA = ImageBase + RVA`。其他格式和内存 dump 先核对工具的 `GetRVA` 与加载方式，不泛化 PE 公式。
- 使用 [scripts/select_methods.py](scripts/select_methods.py) 按名称筛选 `script.json`；`--pe-image-base` 仅用于已确认的 PE RVA。保留同名重载、泛型共享和重复地址，不把映射强行当成一对一。
- 接着使用 [ida-decomp-analysis](../ida-decomp-analysis/SKILL.md)，通过官方 IDA MCP 查询对应函数的指令、伪代码、调用和字段访问。IDA 自动库签名可能误命中极短 getter；用 metadata、偏移与指令一起判断，报告自动名称与元数据的差异。
- IDA → 本技能：出现 `sub_*`、未知对象字段或疑似 IL2CPP 运行时调用时，用 dump 恢复业务类和候选签名，再回 IDA 验证。偏移必须区分对象头、实例字段、静态字段、数组长度和元素区。
- 仅分析时保留只读查询路径。Il2CppDumper 附带的 IDA 导入脚本会批量改名、加注释或应用类型；只有任务包含这些修改时才执行，并核对脚本与当前 IDA API 的兼容性。

## 角色、移动素材与动画

涉及角色图片、皮肤、Prefab、Animator 或 AnimationClip 时阅读 [资源与移动分析参考](references/assets-and-movement.md)。代码描述“选择什么资源、如何控制运动”，资源描述“图像怎样分层、怎样变化”；需要两者对应才能解释移动设计。不要把头像当成战斗帧、把导出的所有 Sprite 当成已播放动画，或把 prefab 初始姿势说成运行时截图。

产物按任务保存在项目子目录，例如 `temp_data/unity-analysis/<任务>/`。交付包括相关类型和地址证据、必要资源 manifest、用户能查看的原图/预览以及未验证的动态行为；不要求用户先理解全部 dump 文件。
