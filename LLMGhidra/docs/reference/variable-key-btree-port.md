# Variable-key B-Tree type 3/4 C++ 迁移证据

## 基线与映射

本迁移单元对应固定基线中的：

- `db.FieldKeyNode`
- `db.FieldKeyInteriorNode`
- `db.FieldKeyRecordNode`
- `db.VarKeyNode`
- `db.VarKeyInteriorNode`
- `db.VarKeyRecordNode`

C++ 实现位于：

- `src/database/include/llmghidra/db/variable_key_nodes.hpp`
- `src/database/src/variable_key_nodes.cpp`
- `src/database/include/llmghidra/db/node_manager.hpp`
- `src/database/src/node_manager.cpp`

行为与布局测试位于 `tests/database/variable_key_btree_tests.cpp`。

## 已保持的磁盘布局

type 3 interior：

```text
NodeType(1)
KeyType(1)
KeyCount(4)

每个 entry:
  KeyOffset(4)
  ChildID(4)

尾部:
  KeyN ... Key0
```

type 4 record leaf：

```text
NodeType(1)
KeyType(1)
KeyCount(4)
PreviousLeafID(4)
NextLeafID(4)

每个 entry:
  KeyOffset(4)
  IndirectFlag(1)

尾部:
  KeyN | RecordN ... Key0 | Record0
```

实现保持以下上游规则：

- byte 1 保存 encoded Field key type，打开已有 node 时与 schema key type 校验。
- type 3 最大 serialized key 长度为 `((bufferLength - 6) / 8) - 8`，使用显式
  guard 防止无符号下溢。
- type 4 inline record 阈值为
  `((bufferLength - 14) >> 2) - 5 - serializedKeyLength`。
- String/Binary key 的 serialized length 包含 4-byte 长度前缀。
- key 和 record 在 type 4 尾部构成连续 packed unit；entry 按 key 正序，尾部数据逆序
  紧凑存储且不留 gap。
- 大记录保存为 4-byte `ChainedBuffer` ID，`record_offset()` 对 indirect record 返回
  负 buffer ID。
- `Schema::force_variable_key_nodes()` 可让 fixed-length Field key 使用 type 3/4。

## 已验证行为

- type 4 在 123-byte DataBuffer 上的 node type、key type、count、leaf IDs、entry offset、
  indirect flag、String key 和 fixed record payload 精确字节。
- type 3 的 key-offset table、child IDs、逆序 packed String keys 精确字节。
- StringField 空字符串与 null key 区分；空字符串可用，null key 被拒绝。
- 最大 key storage length 边界可用，超限 key 被拒绝。
- StringField prefix 排序和 BinaryField key 排序/roundtrip。
- legacy forced variable-key int32 Field 的 type 3/type 4 创建、查询和多 leaf tree。
- 700 条变长 String key 乱序插入形成多层 type 3 tree。
- leaf split、interior split、parent leftmost key 长度变化、parent resize/split、
  sibling merge/rebalance 和 root collapse 路径。
- before/after/at-or-before/at-or-after 跨 leaf 范围查询。
- 多层删除后的 membership、tree consistency、LocalBufferFile save/reopen 和 undo。
- variable record 的 inline → indirect → inline 更新和全部 chained buffer 回收。
- 1-byte 全-null sparse inline record 增长为 4-byte indirect reference，不发生
  `size_t` 下溢。
- 混合 inline/indirect payload 的 split、删除与整树 buffer 回收。
- 新建 type 3/4 构造失败会回滚尚未注册的 buffer；child parent 只在全部 child 成功解析
  后统一发布，不留下 lock 泄漏或部分 parent 绑定。
- indirect record 在修改 leaf 前完成内存序列化和 pending chain 写入；leaf 提交失败会恢复
  原始 bytes 并回收 pending chain；indirect→indirect 使用新 chain 原子替换旧 chain。
- type 3 插入 split、child-key resize split 与 sibling redistribution 使用固定 Java 基线的
  packed-offset 中点/half-space 选择规则，并由会区分旧算法的确定性 4/6、6/7 fixture 锁定。
- 已有 node 的错误 key type和与 entry table 重叠的错误 key offset会被拒绝。
- NodeManager 已能创建、打开、缓存、释放、失效和删除 type 3/4；至此本地 factory
  覆盖 type 0–7。

## 已执行命令

```powershell
& 'D:\App\CMake\bin\cmake.exe' `
  --build --preset windows-msvc-debug `
  --target llmghidra_variable_key_btree_tests -- /m

& 'out\build\windows-msvc\Debug\llmghidra_variable_key_btree_tests.exe'

& 'D:\App\CMake\bin\cmake.exe' `
  --build --preset windows-msvc-debug -- /m

& 'D:\App\CMake\bin\ctest.exe' `
  --preset windows-msvc-debug --output-on-failure

& 'D:\App\CMake\bin\cmake.exe' `
  --build --preset windows-msvc-release `
  --target llmghidra_variable_key_btree_tests -- /m

& 'out\build\windows-msvc\Release\llmghidra_variable_key_btree_tests.exe'

& 'D:\App\CMake\bin\cmake.exe' `
  --build --preset windows-msvc-release -- /m

& 'D:\App\CMake\bin\ctest.exe' `
  --preset windows-msvc-release --output-on-failure
```

结果：Debug 与 Release 全量 17/17 CTest 通过；Debug 和 Release 的 variable-key 专项
测试通过。Release test preset 已加入 `CMakePresets.json`。

## 当前未关闭项

相关 Java 台账继续保持 `REVIEW_REQUIRED`，原因如下：

- 尚未建立固定基线 Java Oracle 的 type 3/4 随机操作差分。
- 尚未完成 Java/C++ 逐 buffer fixture 比较与四向 cross-open。
- Table、IndexTable、FieldIndexTable、Iterator 和 DBHandle 尚未接入。
- malformed node 覆盖仍需扩展到 offset 环、重复 child、broken sibling、损坏 chain 和
  结构化 dbverify 诊断。
- 尚需 Java Oracle 随机序列、底层 BufferManager/ChainedBuffer fault injection、并发只读、
  sanitizer 和 fuzz。

因此本证据关闭 type 3/4 的本地实现工作包，但不满足 Phase C 兼容退出条件，也不能将
对应 Java 文件改为 `PORT`。
