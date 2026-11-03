# Program Model 当前 schema 原生迁移记录

## 状态

`REVIEW_REQUIRED`。本文只记录已经落入正式 C++ 产品源码的迁移边界，不声明构建、测试、
Java Oracle 或 cross-open 已通过。根据当前项目约定，完整生产代码迁移和 Java 剥离闭合前不运行
碎片化测试，所有动态证据统一留到最终验收。

## 已迁移源码边界

- Address、AddressSpace、AddressFactory、AddressRange、AddressSet 与地址运算。
- Language、Register、CompilerSpec、PrototypeModel 和 DataOrganization 的原生描述模型。
- Program metadata、Program transaction、当前 AddressMapDB 编码与 Program image base。
- `Symbols` V4：13 列、稀疏列、七个二级索引、Java UTF-16 locator hash、source/pinned flags、
  namespace、primary、外部符号元数据和持久化 CRUD。
- `Function Data` V3：返回类型、栈信息、calling convention、return storage、vararg/inline/
  no-return/custom-storage/signature-source flags，并与 function Symbol 生命周期绑定。
- `Thunk Functions` V0 及反向枚举、cycle 拒绝和被引用 thunk 的递归删除。
- lazy `Function Tags` V0 / `Function Tag Map` V0：tag CRUD、唯一名称、function/tag 二元映射、
  函数删除与 tag 删除级联，以及 rollback 后 table handle 重新绑定。
- `Variable Storage` V2：`Hash`/`Storage` 与 Hash index、VARIABLE-space storage ID、Ghidra
  `space:offset:size`/特殊 storage serialization 和固定 CRC64；同 hash 候选继续核验完整
  serialization，避免碰撞误复用。
- parameter/local 的 Symbols V4 高层语义：datatype、parameter ordinal、local first-use、storage
  地址、comment、插入/删除 ordinal 归一化、stack local first-use=0、storage overlap 检查及 thunk
  目标函数透传。
- 通用 long-valued `AddressRangeMapDB` 当前 schema：`Range Map - *`、From/To/Value、Value index、
  paint/clear/split/merge、边界 wrapping record 解码/重建和 AddressMapDB key。
- `Range Map - SCOPE ADDRESSES` 上的 Namespace body：set/remove、overlap 拒绝、containing-address、
  nested namespace union、overlapping namespace 枚举以及 address-range move/delete。
- Function body 与 Namespace range map 同步：内部函数 body 非空、entry 属于 body、单一 address
  space、namespace overlap 拒绝，以及 create/update/remove 生命周期同步。
- `Function Data` V0/V1/V2 旧 schema 已加入只读 record 翻译与 upgrade-mode 事务内 V3 表替换；
  V0/V1 补 unknown calling-convention，V0/V1/V2 保留旧 flags 并设置 custom-storage，return storage
  按上游置 null。旧库缺失 `Thunk Functions` 时 read-only 使用空关系，upgrade 创建当前 V0 表。
- `Symbols` V1/V2/V3 旧 schema adapter 已落入原生 C++：V3 拆分 external address/import name、
  variable comment 和 library path，保留 sparse hash/datatype/offset；V1/V2 重建 Java-compatible
  locator hash、label/function primary、parameter ordinal/local first-use，并将旧 AddressMap key 在
  upgrade-mode 重编码为当前 key。read-only 查询按翻译后的记录扫描，不使用错位的 V4 sparse/index
  列；V1 source flags 保留固定上游 adapter 可观察的 `SourceType.ordinal()` 写法，不擅自替换为当前
  storage ID。update-mode 明确拒绝旧 schema，upgrade-mode 在 Program 顶层事务内替换为带七个索引的 V4。
- 无 `ADDRESS MAP` 表的历史数据库现可在 read-only 下继续使用 AddressFactory old-index 编码，并在
  upgrade-mode 从按地址排序的 factory spaces 创建 V1 表；old-index key/key-range 与 decode 路径保持
  成对，供后续 Symbols V0 和 old-function 协调迁移使用。
- `Symbols` V0 upgrade 已按两阶段模型接入：全局静态 symbol 立即重编码为 V4 label，key 0 按旧
  adapter 规则 remap；dynamic rows 被过滤；local rows 暂存原 ID/old-address/name/primary，当前 symbol
  allocator 在函数迁移期间避开这些 ID，Function Data-backed namespace body 建立后再以原 ID 回填。
  V0 read-only/update 保持拒绝，因为上游同样要求协调 upgrade，不能伪造不完整 symbol graph。
- 新增 pre-Function-Data 原生只读 source adapter，覆盖 `Functions` V0/V1、`Stack Variables` V0/V1、
  `Register Parameters` V0、`Shared Ranges - Functions` V0 与 `Shared Map - Functions` V0；在删除任何
  旧表前统一验证 schema 和双索引，并提取 entry、body、return type、stack frame、repeatable comment、
  stack variables 与 register parameters。该 adapter 已进入正式 CMake target，并由 Program 级
  coordinator 消费完整快照后写入当前 manager。
- Program 级 old-function coordinator 已接入 `Program::open(UPGRADE)`：仅在旧 `Functions` 存在时
  创建缺失的当前 `Function Data`/`Thunk Functions`，恢复 primary/default 函数名、body、return
  datatype、stack purge/return/local size 与 custom-storage，并迁移 register-first 的参数顺序、栈
  参数/局部变量、comment 和 `.dup` 重名处理。全部目标记录成功后才删除五张旧 function 表和两张
  废弃 variable 表，再执行 Symbols V0 local finalize；外层 Program transaction 保证失败整体回滚。
- 新增 Ghidra `Comments` V1 原生 manager，列顺序固定为 EOL/Pre/Post/Plate/Repeatable；支持当前 CRUD、
  V0 read-only、V0→V1 与 AddressMap rekey 协调升级。old-function 的 RepeatableComment 写入正式
  Comments 表，已有 plate comment 随整表升级保留，不再暂存到非兼容私有字段。
- 新增显式 `ProgramArchitecture` 绑定：compiler-spec `DataOrganization`/Endian 与 register name→
  address/size 映射由原生 SLEIGH `Translate::getAllRegisters()` 构造。旧函数变量迁移据此解析寄存器
  和动态 datatype size，不硬编码 x86 或默认 32 位 ABI；缺少绑定时整个升级事务明确失败并回滚。
- 新增旧 `VariableStorage`（无空格）V0/V1 source adapter：完整 schema 校验、全表/按 ID/namespace
  提取、old AddressMap storage 解码及延迟删除。固定上游 adapter 不要求 NamespaceID 物理索引，
  namespace 查询使用兼容扫描，避免拒绝合法的无索引历史项目。
- 新增 Ghidra References 原生 manager，物理布局保持 `FROM REFS` V0 与 `TO REFS` V1 的冗余
  directional tables，不改成自定义单表。inline RefList 使用 8-byte big-endian related-address key、
  split SourceType flags、RefType、byte operand、可选 symbol ID 与 offset/shift；达到 1700 条时切换
  `FromBigRefList_<unsigned-hex-key>` / `BigRefList_<unsigned-hex-key>` V1，并为 Address 列创建索引。
- References 高层语义已覆盖双向 add/remove、primary 唯一化、symbol association、RefType/ref-level
  更新、FROM/TO/范围删除与移动、stack/register 只写 FROM、external-entry point 和 transaction/cache
  生命周期；Symbol 删除/范围删除通过 Program 级回调先清除对应 reference symbol ID，避免悬挂关联。
  Address/AddressFactory/AddressMap 同步加入 Ghidra `EXT_FROM_ADDRESS` 的 `-2` 稳定键，与普通
  `NO_ADDRESS` 分离。
- `TO REFS` V0、AddressMap rekey、旧 `Memory References` shared table、`Stack References` 与
  `External Entries` 已接入 read-only 或 upgrade 路径。升级以 FROM/shared 语义快照重建当前双向表，
  inline/BigRef 中的 owner/related address 全部重编码；目标表与 BigRef 索引完整写入后才删除旧表。
- Program 级协调迁移现会在旧 variable symbol 写回前正规化 namespace-encoded register/stack
  reference；指向旧 VARIABLE-space 地址的 reference 会先移动到对应实际 storage（无有效 storage
  时删除该失效目标引用），再使用显式 `ProgramArchitecture` 的 datatype metrics 构造当前
  VariableStorage。
  parameter/local/global variable symbol 保留 ID 后改写为 VARIABLE-space 地址；缺失或非法历史 storage
  落为 `BAD_STORAGE`。所有引用、storage 与 symbol 成功写入后才删除旧 `VariableStorage` source table。
- ProgramDataTypeManager 当前 schema adapter 层：
  - `Calling Conventions`
  - `Built-in datatypes`
  - `Categories`
  - `Arrays`
  - `Typedefs`
  - `Composite Data Types`
  - `Component Data Types`
  - `Function Definitions`
  - `Function Parameters`
  - `Default Settings` 与 `Default Settings Names`
  - `Pointers`
  - `Enumeration Data Types`
  - `Enumeration Values`
  - `DT_PARENT_CHILD`
  - `Data Type Archive IDs`
  - `DataTypeManager` 版本属性
  - `Instance Settings` 与 `Instance Settings Names`
- DataType ID 高字节 kind 编码、category、calling convention 和 default/instance settings 的
  原生持久化入口。
- Builtin、Array、Pointer、Typedef、Enum/EnumValue、Composite/Component、Function Definition/
  Parameter 的表级语义对象创建、加载、枚举与受引用删除。
- `DT_PARENT_CHILD` 依赖维护；类型删除会拒绝破坏仍被引用的 child，Composite/Function Definition
  删除会同步清理 component/parameter，Enum 删除会同步清理 value。
- 无独立表的 BitField ID 编解码：32 位 base index、base kind、extra-storage、bit offset、bit size，
  并把虚拟 BitField 对 base typedef/enum/integer 的引用纳入删除保护。
- Function Data 的返回类型 ID 已接入同一 DataTypeManager 完整性校验。
- DataType 当前 schema 原位更新：保留主类型 ID，复用仍属于原 parent 的 EnumValue、Component、
  FunctionParameter 行 ID，新增子行分配新 ID，删除缺失子行，并按最终 children 重建
  `DT_PARENT_CHILD`；所有 child、identity、category/name 和循环约束在主记录写入前静态校验。
- DataType 冲突解析入口：`RENAME_AND_ADD`、`USE_EXISTING`、`REPLACE_EXISTING` 与
  `REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD`，包括 `.conflict`/`.conflictN` 名称分配、同位置
  conflict-family 等价复用、same-kind 原位替换和 cross-kind 引用重定向。
- 递归等价与依赖查询覆盖 Array、Pointer、Typedef、Enum、Composite、Function Definition 和
  虚拟 BitField；replacement 会预检循环，重写 parent records 与 bitfield base 后再删除旧类型。
- ProgramDataTypeManager 的外部 replacement/delete 扩展已接入 Symbols V4 datatype 列和
  Function Data V3 return datatype；后续 Listing/Code manager 将接入同一回调闭包。
- `Data Type Archive IDs` 已具备原生 CRUD、replace、dirty/last-sync 状态；可按
  `(source archive ID, universal ID)` 查询、关联、解除关联和 source-sync 更新。Universal ID
  生成位布局按上游 `UniversalIdGenerator` 的 time/session/sequence 结构迁移。
- 本地修改只推进 last-change 并标记对应 source archive dirty；source-sync 同步
  source-sync/last-change；preserve 模式用于 archive 重映射而不伪造修改时间。
- DataOrganization 已使用与上游一致的 machine/pointer/wchar/size-alignment 默认值，并按
  `TreeMap.floorEntry` 语义查询 size alignment；cspec 的 `bitfield_packing` 子元素被拆分为
  MS convention、type-alignment-enabled 与 zero-length-boundary，endianness 仍由 Language
  单独提供。
- DataType 原生 metrics 已覆盖固定/动态/零长度、length/aligned-length/alignment、Builtin
  primitive、Pointer、Enum、Array、Typedef、Composite、Function Definition 和虚拟 BitField；
  Pointer 不递归 referent，是自引用 composite 的尺寸依赖断点。
- Structure/Union 布局入口显式接收 compiler-spec `DataOrganization` 与 `Endian`，不使用宿主 ABI
  默认值；源码迁移覆盖 default/explicit/no packing、minimum/machine/absolute-max alignment、
  component alignment LCM、最终长度对齐、GCC/MSVC bitfield allocation group、零宽 bitfield、
  type-alignment/zero-boundary 控制及大小端 bit offset 重写。
- Composite 专用高层操作已覆盖 insert、批量 delete、replace、reorder 和 packing/minimum-alignment
  更新；布局写回 ordinal/offset/length/virtual-bitfield-ID/composite length/alignment。布局感知
  DataType update 与显式 propagation 会收集 parent closure，跨 Array/Typedef/Composite/Function
  Definition 按 child-first 拓扑顺序更新，并在 Pointer 处停止传播。
- replacement 和 layout propagation 完成后会折叠因 child 重定向而等价的 Array/Pointer 自动类型，
  保留稳定目标 ID、重写父引用并删除重复行。
- 跨 archive 对象图 resolve 接受显式 source lookup、category mapper 与 archive mapper；foreign
  EnumValue/Component/FunctionParameter 行 ID 会在目标库重建。Composite/Function Definition
  先建立目标 placeholder，再解析 child，因此 `struct node { node *next; }` 一类 Pointer 递归不需要
  无效临时引用；完整定义写回后执行 conflict-family 等价折叠，并覆盖四种 conflict policy 及
  same-kind/cross-kind replacement 路径。
- 旧 DataType table family 已加入统一两阶段协调迁移：Arrays V0、Pointers V0/V1、Typedefs V0/V1、
  Composite V0/V1/V2–V4/V5、Function Definition V0/V1、Function Parameter V0、Enum/EnumValue V0、
  Default/Instance Settings V0，以及 Calling Convention、Function Definition/Parameter、Enum/Value、
  ParentChild 和 SourceArchive 的历史缺表路径。所有 schema 均按固定列类型、列名和 key 类型识别；
  newer/未知布局拒绝，UPDATE 模式拒绝需要迁移的数据库。
- READ_ONLY 旧库会把翻译结果绑定到 `DatabaseHandle::scratch_database()` 的 current-schema tables，
  二级索引查询在 scratch 视图上使用等价扫描，不污染源数据库。UPGRADE 在删除任何源表前完成全部
  staging、Settings name/value 配对、calling-convention ordinal 正规化和依赖重建，再在 Program 顶层
  事务内统一替换目标表与索引，任何异常由外层事务整体回滚。
- Instance Settings 在 AddressMapDB 刚升级时使用 old-index decode/current-key encode 重写 association；
  缺失 `DT_PARENT_CHILD` 会从 Array/Pointer/Typedef/Component/Function return/parameter 记录重建完整
  parent-child graph。Composite V5 的负 ordinal trailing flex-array 会转换为同 category 的零元素
  Array，更新 component ordinal/offset 与 composite count；packed structure 由显式 compiler-spec
  `ProgramArchitecture` 重排，缺少该架构时拒绝不完整的可写升级。
- 历史缺失 SourceArchive table 会恢复 LOCAL row；V0 Typedef/Composite/FunctionDef/Enum 使用原生
  UniversalIdGenerator 等价布局产生稳定 identity，`NO_SOURCE_SYNC_TIME`/`NO_LAST_CHANGE_TIME` 固定按
  当前上游的 `0` 写入。Program managers 完成 datatype rewrite callback 绑定后，再执行固定旧 archive
  ID 替换和 root obsolete typedef→existing builtin 重定向，避免先删类型后留下 Symbol/Function 悬挂 ID。
- `Memory Blocks` V0/V1/V2→V3、`Sub Memory Blocks` V3 与 `File Bytes` V0 已进入原生 manager；
  READ_ONLY 使用 scratch current-schema 视图，UPGRADE 先 staging 再事务内替换，AddressMap 刚升级时
  current V3 block start 和 mapped source key 会重编码。API 覆盖 initialized/uninitialized、原生
  ChainedBuffer、FileBytes original/layered backing、byte/bit mapped、split/join、conversion、source-info
  与 address-source-info，并将 move/delete 联动到 References、Namespace、Symbols、Functions、Comments。
- Memory 打开时校验三表完整性、block name/flags/range/sub-block partition、orphan sub-block、backing
  buffer 长度、FileBytes buffer family/range 与 mapped source；byte mapping source-offset 运算显式拒绝
  溢出，mapped 递归读写使用同一 active-address 链检测 cycle。
- `Overlay Spaces` V0/V1 原生 manager 在 `PersistentAddressMap` 前构造，使持久化 overlay name 先恢复
  到 AddressFactory。Program 已接入 create/rename/remove 与 AddressMap rename/delete；Memory 的
  overlay block 创建会合法化名称并分配唯一后缀，create/split/join/move/remove 后重建 overlay
  regions，空 overlay 自动清理，并固定拒绝 OTHER overlay block 的 move/split。join 边界会合并
  相邻 uninitialized、连续同源 FileBytes 与合计不超过 1 GB 的 ChainedBuffer sub-block。
- Equates V0 与 Equate References V0/V1 已进入原生 manager，固定 name/value 及 equate/address index
  schema；V0 reference 迁移补 `Varnode Hash=0`，AddressMap upgrade 会重编码 reference address。
  Equate/reference CRUD、operand/dynamic-hash replacement、range move/delete、owner 级 cascade 和 orphan
  equate 清理已接入 Program，并随 Memory block move/delete 触发。
- Listing 存储核心已迁移 Data V0、Instructions V0/V1、Prototypes V0/V1、ContextTable V0/V1；
  READ_ONLY 使用 scratch current-schema tables，UPGRADE 两阶段替换，AddressMap upgrade 会重编码三类
  address。Instructions V0 补 flags=0，Prototypes V0 归一化负 ID、补 delay-slot=false；ContextTable
  V0 的 comma-separated signed words 使用 big-endian two's-complement 转成 Java BigInteger 等价十进制。
- Prototype/context、Instruction/Data CRUD、prototype owner 校验、flags length override、datatype metrics、
  dynamic-data available range、code-unit overlap、range move/delete 和 datatype replacement 已接入 Program
  的 Memory/DataType 生命周期。持久化继续使用原始 Ghidra 表，不引入 C++ 专用 Listing container。
- CodeManager 语义协调层已落码，直接组合 Listing、Memory、Comments、References 与 RegisterContext，
  覆盖 code-unit at/containing/before/after、defined/undefined ranges、instruction/data 创建、fallthrough、
  comments、range clear/move 和 processor-context locking；没有重建另一套 code-unit 存储。
- RegisterContext 当前 schema 已落码：保留 `Range Map - Register_<base>` V0、long Address key、To 与
  BinaryField Value、无 Value index；mask/value 均按 Ghidra big-endian significance 布局，base/sub-register
  merge/remove、default overlay、range move/delete 与 ProgramArchitecture 寄存器绑定已接入 Program。
- 旧 Program Context ByteField 表族已落码 read-only/upgrade 迁移：识别并校验
  `Range Map - ProgContext<signed-offset>` V0，按 old AddressMap 解析 wrapping ranges，把各 storage byte
  的 change points 合并为 base-register BinaryField mask/value。little-endian storage byte会转换到
  big-endian significance 布局；processor-context 仅保留显式 child register mask。READ_ONLY 绑定独立
  scratch AddressMap/current tables，不修改源库；UPGRADE 完成全部 scratch staging 和目标表复制后才删除
  旧表。AddressMap 刚升级时 current context ranges 同样先解码为语义 range，再以新 key staging 后整体
  替换。ProgramArchitecture 已扩展 bit length、LSB、base-register 和 processor-context 元数据，缺失架构时
  明确拒绝可能丢位的旧 context 迁移。
- pspec 与 cspec 的 `context_data/context_set/set` 现均由 LanguageRegistry 保留完整 range/name/value
  属性；RegisterContext 默认值入口先应用 pspec、再以 cspec 覆盖，并把 SLEIGH absolute context-bit
  range 转为 Ghidra big-endian mask/value。不同 context fields 的同 range defaults 会按 mask 合并，不再
  相互覆盖。SLEIGH 初始化现在通过 `SleighContextMetadataCollector::registerVariable()` 自动收集
  absolute context-bit fields，再由 `ProgramArchitecture::from_sleigh()` 绑定 processor-context base。
  `ProgramContextDatabase` 的低层查询直接叠加 ProgramDB current/default register context；标准
  `.sla` 的 `ContextSymbol` base varnode 同步由 `SleighBase` 暴露；即使该 context register 因 alias
  未成为 `getAllRegisters()` 的 canonical name，ProgramArchitecture 也会按原 storage 显式注入，并由
  flat register containment 恢复 largest-base/sub-register/LSB 元数据。`setVariable`、region 和
  change-point 写入通过兼容变更回调回写 `Range Map - Register_*`，不再把
  独立 `ContextInternal` 当作 Program 状态。pspec 后 cspec 的 tracked settings 按地址空间 range
  进入原生 tracked provider，且不会错误写入 ProgramRegisterContextDB 持久化表。
- ExternalManager 已落码且没有自建表：library/path/location 继续存于 Symbols V4，external function 继续
  使用 Function Data V3；包括 external 地址分配、namespace/library 归属、original import/program address
  查询、reuse 以及 label→function 保留 symbol ID 的原位提升。
- Relocations V6 当前 schema 已落码：Index key、Address index、status/length flags、BinaryCodedField long[]、
  stored/deferred original bytes 和 symbol name 均保持固定上游布局，并通过 Memory FileBytes source-info
  解析 deferred bytes。
- Relocations V1–V5 adapter/upgrade 已落码：V1–V4 从 address key 取址，V5 从 indexed Address column
  取址，V2 单 long Value 转为 BinaryCodedField long[]，其余缺失列保持 null；READ_ONLY 按旧 schema
  即时翻译，UPGRADE 先写 scratch V6、用 old AddressMap 解码并以 current AddressMap 重编码，全部成功后
  才替换原表。AddressMap 刚升级时已有 V6 表也执行同样 rekey。Program DB V26 之前的 UNKNOWN rows
  会在 Memory 和 compiler DataOrganization 就绪后，根据 loaded+initialized、stored bytes、下一条
  relocation、地址空间边界以及 FileBytes original/current byte diff 补齐 status/deferred length。
  `Program` 不再在 manager 构造前提前写高 DB Version，而是在所有升级步骤成功后才写入版本 32。
- Properties V0 registry 及 int/long/string/void `Property Map - *` 当前 schema 已落码，涵盖 CRUD、
  range delete/move 与 Program memory 生命周期。object property 保留任意 Saveable schema 的原生 DB table，
  由 C++ schema-specific adapter 直接访问，不以 Java reflection、JSON 或私有 blob 替代。
- 历史 `.lang`、protected segmented address space、`.trans` 与 native translator endpoint/factory/chain
  已进入原生 Program Model。LanguageTranslator 现覆盖 address-space/address/register/context value/
  compiler-spec/VariableStorage translation，`PersistentAddressMap`、Overlay、Symbol external address、
  Function return storage、Variable Storage、Register Context 与 DataType layout 已纳入 Program 顶层原子
  language-change 编排；失败路径会恢复旧 architecture/address factory/runtime binding。Program memory
  ranges 会在 context gap-fill 前翻译到目标 AddressFactory，避免把旧空间范围写入新 context 表。
- `ProgramContextDatabase::decodeFromSpec()` 已恢复调用标准 C++ `ContextInternal` pspec/cspec decoder，
  不再要求 Java 或公开一个永久抛错入口；tracked sets 通过虚拟 `createSet()` 进入 Program provider，
  parsed ProcessorSpec/CompilerSpec 仍是持久化 context defaults 的权威来源。
- `Bookmark Types` V0 与 per-type `Bookmarks<ID>` V3 manager 已接入 Program；覆盖类型/category、CRUD、
  address move/delete、统一 V1/V2 表升级、AddressMap rekey，以及 pre-table `OldBookmark` object property
  的 read-only view/upgrade-mode 物理迁移。迁移继续使用原 Ghidra 表和 property schema。
- 原生 `ProgramLoadImage` 已加入 headless runtime target，直接从 ProgramDB MemoryManager 提供字节、
  initialized/uninitialized/code/data/readonly section，并从 FunctionManager 枚举函数符号；该通路无
  Java callback、协议桥或替代内存容器。
- 原生链接图已把 decompiler 与 SLEIGH 共同使用的 `marshal/space/float/address/pcoderaw/translate/
  opcodes/globalcontext/xml` 收束到唯一 `ghidra_native_common` 静态库；`ghidra_decompiler_core` 与
  `ghidra_sleigh` 只编译各自专属源码，避免最终 headless 进程同时链接两份公共实现。Java bridge
  继续是隔离、默认关闭且排除在产品 all/install 图之外的最终 Oracle 工具。

上述表按固定上游 `DataTypeManagerDB.initializeAdapters()` 顺序创建；`DataTypeManager` 属性表在
core adapters 后创建，Program instance settings 在其后创建，以保留可观察的 table/root 分配顺序。

## 主要上游行为来源

- `ghidra.program.database.map.AddressMapDB`
- `ghidra.program.database.ProgramDB`
- `ghidra.program.database.OverlaySpaceDBAdapterV0/V1`
- `ghidra.program.database.ProgramAddressFactory`
- `ghidra.program.database.mem.MemoryMapDB` 与 `MemoryMapDBAdapterV0/V1/V2/V3`
- `ghidra.program.database.mem.SubMemoryBlock`、`FileBytes` 与 mapped sub-block implementations
- `ghidra.program.database.symbol.EquateManager`
- `ghidra.program.database.symbol.EquateDBAdapterV0` 与 `EquateRefDBAdapterV0/V1`
- `ghidra.program.database.code.CodeManager`、`DataDBAdapterV0` 与 `InstDBAdapterV0/V1`
- `ghidra.program.database.code.PrototypeManager` 与 `ProtoDBAdapterV0/V1`
- `ghidra.program.database.symbol.SymbolDatabaseAdapterV4`
- `ghidra.program.database.function.FunctionAdapterV3`
- `ghidra.program.database.references.ReferenceDBManager`
- `ghidra.program.database.references.FromAdapter*` 与 `ToAdapter*`
- `ghidra.program.database.references.RefListV0`、`BigRefListV0` 与 `RefListFlagsV0`
- `ghidra.program.database.references.OldStackRefDBAdpater`
- `ghidra.program.database.symbol.OldVariableStorageManagerDB`
- `ghidra.program.database.data.DataTypeManagerDB`
- `ghidra.program.database.data.ProgramBasedDataTypeManagerDB`
- `ghidra.program.database.data.ProgramDataTypeManager`
- `ghidra.program.database.data.DataTypeDB` 与 `SourceArchiveDB`
- `ghidra.program.model.data.DataTypeConflictHandler` 与 `DataTypeUtilities`
- `ghidra.program.model.data.DataOrganizationImpl` 与 `BitFieldPackingImpl`
- `ghidra.program.model.data.AlignedComponentPacker`、`AlignedStructurePacker` 与
  `CompositeAlignmentHelper`
- `ghidra.util.UniversalIdGenerator`
- `ghidra.program.database.data.*AdapterV*` 的当前 schema adapter

## 尚未闭合

- 新迁移 DataType metrics/packing/edit/propagation 源码的最终统一构建、Oracle、raw-record 与
  大小端/compiler-spec 矩阵仍未执行，状态保持 `REVIEW_REQUIRED`。
- 新迁移 automatic-type/conflict-family 去重与跨 archive 递归 resolve/merge 的最终统一动态矩阵。
- 旧 DataType/ProgramDB schema 协调源码已落码；最终统一 raw-record、只读不变性、失败回滚和
  Java/C++ cross-open 动态矩阵尚未执行，保持 `REVIEW_REQUIRED`。
- old-function、References 与旧 VariableStorage Program 级写回已落码但尚待最终统一动态验收。
  Namespace 其余旧 schema、
  auto-parameter、forced-indirect 及完整 prototype/calling-convention storage 分配仍待迁移。
- Memory/Overlay 生产源码已开始落码并接入，仍缺 rollback/undo overlay identity、剩余损坏矩阵和
  最终统一动态验收；Equate 动态验收；Listing/Code 仍缺 native SLEIGH prototype identity/parse、
  完整 delay-slot/flow orchestration和 Comment History。RegisterContext 的 pspec/cspec default parser/
  override/apply、SLEIGH context-field metadata producer、ProgramDB-backed ContextDatabase 及 tracked
  settings provider 及 context points/tracked points XML 投影、language translator chain、Program 级
  language-change 事务和 `decodeFromSpec` 直连已落码，仍缺 `ProgramLanguageChangeServices` 的完整
  native SLEIGH reset/rollback、ARM context repair、全 instruction redisassembly、calling-convention
  reconciliation、compiler-option reset、post-upgrade handler registry 与 pspec fixups；
  旧 Program Context 迁移源码以及 Relocation V1–V6 升级/status refinement
  源码已落码但尚待最终统一动态验收；Bookmark current/legacy schema 已落码，Property Maps 仍缺除
  OldBookmark 外其余 Headless 可达 Saveable object adapters。Tree/Module、SourceMap/SourceFile、Comment
  History、剩余 Namespace/Function/Listing 与这些 managers 的跨 manager 事件/删除闭包仍需继续迁移。
- `ProgramLoadImage` 已形成 ProgramDB 字节/section/function-symbol provider，但完整 Program-backed
  `SleighArchitecture`、overlay address-space installation、Decompiler symbol/type/comment/cpool provider、
  decompile session、Loader、Analyzer、公开 API/CLI 与安装入口尚未闭合。
- 当前源码的最终统一构建、测试、Oracle、四向 cross-open 和 raw buffer parity。

这些未闭合项继续位于 Phase D 必做范围，不得改名为 optional、future work 或后续版本。
