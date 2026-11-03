---
name: unity-il2cpp-analysis
description: 用 Il2CppDumper 分析 Unity IL2CPP 原生模块与 global-metadata.dat，恢复类、字段偏移、方法地址，并关联角色、皮肤、Prefab 与动画资源；方法行为交由 ida-decomp 核对。
metadata:
  short-description: 恢复 Unity IL2CPP 类型、地址并关联资源
---

# Unity IL2CPP 分析

Il2CppDumper 只给类型与地址地图，不含方法体。算法、边界与副作用用 [ida-decomp](../ida-decomp/SKILL.md) 核对；角色外观与动画沿序列化引用取原始资源。

## 输入

- Windows：`GameAssembly.dll` + `<游戏名>_Data/il2cpp_data/Metadata/global-metadata.dat`；主 EXE 只是启动器。
- Android：对应架构的 `libil2cpp.so` + metadata。模块与 metadata 必须同一构建，记录平台、架构、Unity 版本。
- 只有 `Managed/Assembly-CSharp.dll` 即 Mono 后端，改用 .NET 反编译器，不走 IL2CPP 流程。
- 先复用已有 dump；工具查 `tools/Il2CppDumper/`，不重装、不改全局配置。

## 运行

1. 核对可执行产物、`config.json`、目标框架；仅有源码时用 `dotnet build` 构建到任务子目录。
2. 显式传入模块、metadata 与**已存在的输出目录**；独立副本中设 `RequireAnyKey=false`。
3. 退出码不可信（异常被捕获仍返回 0），须查日志与必需产物。
4. 用 `rg` 或有界脚本检索 `dump.cs`、`script.json`，勿灌入全量 dump。

| 产物 | 可用 | 不可断言 |
|---|---|---|
| `dump.cs` | 层级、字段偏移、签名、方法 RVA | 空方法体=无逻辑，或这是原始源码 |
| `DummyDll/` | 类型布局，供资源工具生成 type tree | 占位方法体是真实实现 |
| `script.json` | 方法名、签名、地址映射 | 名称即行为，地址即运行时 VA |
| `il2cpp.h` | 原生对象布局 | 可无条件套用 IDA |
| `stringliteral.json` | 字符串与地址线索 | 出现过即已执行 |

解析失败先查文件配对、架构、格式与工具版本。不要凭 Unity 版本号设 `ForceVersion`（只影响原生解析器）。加密、混淆、内存 dump 重定向须记录限制，不得以空输出冒充成功。

## 与 ida-decomp 协作

- 传给 IDA：模块指纹、候选方法名/签名、地址值及语义、字段偏移。PE 的 `ScriptMethod.Address` 是 RVA，`VA = 已知 ImageBase + RVA`；其他格式先核对 `GetRVA` 与加载方式。
- [scripts/select_methods.py](scripts/select_methods.py) 按名筛 `script.json`；`--pe-image-base` 仅限已确认的 PE。保留重载、泛型共享与重复地址，不假设一对一。
- 用 [ida-decomp](../ida-decomp/SKILL.md) 查指令、伪代码、调用与字段访问。库签名可能误命中极短 getter，须 metadata、偏移、指令三方一致，并报告自动命名差异。
- 反向：遇到 `sub_*`、未知字段或疑似运行时调用，用 dump 恢复业务类再回 IDA 验证。偏移须区分对象头、实例/静态字段、数组长度与元素区。
- 仅分析时保持只读；Il2CppDumper 的 IDA 导入脚本会批量改名加类型，只在任务需要时使用并核对 API 兼容性。

## 资源与动画

角色图、皮肤、Prefab、Animator/AnimationClip 用 UnityPy 读 serialized assets；`dump.cs`/`DummyDll` 提供类型与字段布局。代码决定选什么资源与如何运动，资源决定如何分层与变化。不要把头像当战斗帧、把全部 Sprite 当已播放动画、把 prefab 初始姿势当运行时截图。

产物存 `temp_data/unity-analysis/<任务>/`：类型/地址证据、资源 manifest、可打开的图或动画、未验证项。
