# Unity 资源与角色移动分析

## 从类型恢复资源引用

UnityPy 等资源读取工具与 Il2CppDumper 分工不同：Dumper 恢复代码元数据，资源工具读取 serialized assets。按实际 Unity 版本加载资源，保留同目录的 `.resource`、`.resS` 和外部 bundle；只复制 `.assets` 可能导致纹理数据缺失。

先索引对象类型、资产文件、Path ID、名称和外部依赖。`path_id` 只在所属资产文件内唯一；本文件 `m_FileID=0`，非零 File ID 需经 externals 表解析，不把所有引用都查成本文件。优先沿已知配置引用定位，而不是只按名称匹配。

type tree 被剥离时，可从 `DummyDll` 生成目标类型的树，例如：

```python
import UnityPy
from UnityPy.helpers.TypeTreeGenerator import TypeTreeGenerator

env = UnityPy.load(str(resource_path))
generator = TypeTreeGenerator(unity_version)
generator.load_local_dll_folder(str(dummy_dll_dir))
env.typetree_generator = generator
for obj in env.objects:
    if obj.type.name != 'MonoBehaviour':
        continue
    # 先解析头和脚本身份，不对所有未知 MonoBehaviour 做完整反序列化。
    head = obj.parse_monobehaviour_head()
    script = head.m_Script.read()
    if script.m_ClassName not in selected_classes:
        continue
    fullname = '.'.join(filter(None, [script.m_Namespace, script.m_ClassName]))
    nodes = generator.get_nodes_up(script.m_AssemblyName, fullname)
    tree = obj.read_typetree(nodes=nodes)
    # 验证消耗字节数、引用目标类型与关键字段，再保存选定结果。
```

依赖安装到任务 venv，避免混入 IDA 的 Python。上述 API 以安装版本为准；UnityPy 的 `TypeTreeGenerator` 可能还需 `TypeTreeGeneratorAPI`。生成树后仍需验证布局：MonoBehaviour header 中的 `m_Script`、名称和目标类型是独立身份依据；重建树若出现错位指针，应记录并交叉验证，不把任何已解出的字段无条件当真。

图像优先用 `Sprite.image` 导出以解析 atlas、裁剪和打包旋转；整张 Texture2D 不等于一张角色图片。manifest 记录配置→皮肤→prefab/icon、资产文件和各 Path ID。默认皮肤、所选皮肤和替换皮肤分别根据实际引用判断。

字段名为 `animPrefab` 的对象可能只用于选人界面展示，实际战斗的 Animator 位于另一个 `prefab`。比较组件、controller 和 clip 引用，确认哪套包含移动状态后再分析；不能仅凭“动画 prefab”名称选定目标。

## 移动素材的设计问题

用户问“人物如何移动”时，至少区分以下证据层，并根据实际发现选择展示方式：

| 层 | 查询对象 | 需要回答的问题 |
|---|---|---|
| 美术素材 | Sprite、Texture2D、atlas | 是整人逐帧图、身体部件图，还是二者混合？有几种朝向？ |
| 角色装配 | GameObject、Transform、SpriteRenderer、骨骼组件 | 身体、头、手脚、武器如何分层，pivot 和父子层级如何安排？ |
| 动画 | AnimatorController、AnimatorOverrideController、AnimationClip、BlendTree | Idle/Walk/Run 状态如何切换，帧率、时长、循环、位置/旋转/缩放曲线怎样设计？ |
| 控制代码 | 输入、移动控制器、速度与动画参数方法 | 输入如何变成运动，怎样加减速、朝向翻转、触发动画和同步速度？ |

沿角色动画 prefab 的 GameObject→组件→Transform 子节点递归读取，记录 active/enabled、局部 TRS、SpriteRenderer 的 Sprite、颜色、flipX/flipY、sorting layer/order。再查 Animator 的 controller、层、状态、transition 条件、参数、clip 引用；controller 覆盖表和 BlendTree 同样要追踪。

AnimationClip 中 Sprite 的 PPtr 曲线说明逐帧换图；Transform 的 position/rotation/scale 曲线说明部件运动；骨骼/蒙皮组件及对应曲线可能说明骨骼动画。clip 数据可能存在 binding table、streamed/dense/constant clip 等编码形式，必须核对实际格式后解码。没有直接 `m_EditorCurves` 不等于没有动画；只列 clip 名不能证明动画内容。

## 连接移动代码

用 `dump.cs` 筛选输入、速度、加速度、朝向与 Animator 参数字段，用 `script.json` 把 Update/FixedUpdate、移动方法和动画状态 setter 交给 [IDA 技能](../../ida-decomp-analysis/SKILL.md)。实际代码决定以下细节，不能凭字段名填答案：

- 是否归一化斜向输入，使用 `deltaTime` 还是 fixed timestep；
- 位置积分、Rigidbody/CharacterController 或 Transform 的移动方式；
- 起停速度、加减速、动画速度是否随实际位移同步；
- 朝向由水平输入、速度、目标位置还是瞄准方向控制；
- 动画阈值、Idle/Walk 切换、受击/攻击是否覆盖移动状态。

## 可查看的证据

导出关键部件图并画装配层级；逐帧换图可输出联系表/GIF，部件动画在曲线和采样方式已核对后按时间重建预览。处理 atlas trim、pivot、pixels-per-unit、父级变换、镜像和 sorting order；未经完整解码的拼装图标注“prefab 初始姿势”或“局部动画重建”，不能声称是完整游戏运行效果。

报告写清角色配置、prefab、controller、clip 的资产文件和 Path ID，clip 时长/采样率/循环设置，关键曲线或帧序列，以及控制方法的模块地址。把“原始资源事实”“重建可视化”“IDA 静态行为”和“尚未验证的运行效果”区分开，提供用户能实际打开的图片/动画，而不是只交付资源名称列表。
