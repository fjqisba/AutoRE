# NodeManager type 0–7 横向矩阵证据

## 固定基线与范围

对应固定基线 `Ghidra_12.1.3_build`、commit
`8b4c91d4d5bd1549622bfbade0df199585b98365` 中的 `db.NodeMgr`，以及 B-Tree
node type 0–7。C++ 实现和测试位于：

- `src/database/include/llmghidra/db/node_manager.hpp`
- `src/database/src/node_manager.cpp`
- `tests/database/node_manager_tests.cpp`

状态保持 `REVIEW_REQUIRED`：本文证明本地横向语义，不替代 Java Oracle、逐 buffer fixture
或跨实现重开。

## schema 与 node type 矩阵

| profile | key / payload | interior | leaf |
|---|---|---:|---:|
| long-fixed | int64 / fixed | 0 | 2 |
| long-variable | int64 / variable | 0 | 1 |
| variable-key | String / fixed | 3 | 4 |
| fixed-fixed | int32 / fixed | 5 | 7 |
| fixed-variable | int32 / variable | 5 | 6 |

测试显式收集并断言上述矩阵恰好覆盖 type 0–7。create 入口现在同时校验 key family
和 payload 长度类别；错误 factory 不分配 buffer、不增加 lock 且不污染 cache。

## 已验证契约

- create → release → open 的 type dispatch、hard-cache identity 和单一 DataBuffer lock。
- cached/uncached wrong-family getter 均确定性拒绝，异常后 lock/cache 保持不变。
- clean read-only release 会释放、移除 cache 并失效外部 handle；dirty read-only release
  确定性拒绝且不改变状态。
- 三个 key family 的 stale handle `key_field()` 统一抛 `logic_error`，不再空指针崩溃。
- `release_nodes()` 对新增、只读重开、删除分别报告正确 record count delta，重复调用幂等。
- foreign NodeManager delete 与 double delete 拒绝；合法 delete 和析构释放均完成 invalidation、
  lock 释放和 buffer 回收。
- 两叶一根的 parent/root traversal 和有序 child buffer references。
- 五个 profile 使用固定 seed 执行 96 条乱序 insert、replace、lookup hit/miss、partial delete、
  release/reopen、membership 校验、root collapse 和 final reclamation。
- type 0–7 均覆盖非法 type byte 和负 key count；open 异常不泄漏 lock、不污染 cache，恢复
  合法 bytes 后可重新打开。

## 当前未闭合项

- 固定 Java 基线的相同随机 operation replay 与逐 buffer byte comparison。
- Java/C++ 四向 cross-open。
- duplicate/dangling child、cycle、broken sibling、overlapping offset、损坏 indirect chain 的
  全组合 corruption 与结构化 dbverify 诊断。
- BufferManager/ChainedBuffer fault injection、sanitizer、并发只读和持续 fuzz。
- Table/Index/Iterator 接入后的 transaction 与索引同步语义。

因此 WP-C3.2 的本地横向矩阵完成，但 `NodeMgr.java` 及 node 0–7 仍不得标记为 `PORT`。

## 已执行门禁

```powershell
& 'D:\App\CMake\bin\cmake.exe' `
  --build --preset windows-msvc-debug `
  --target llmghidra_node_manager_tests -- /m

& 'out\build\windows-msvc\Debug\llmghidra_node_manager_tests.exe'

& 'D:\App\CMake\bin\cmake.exe' --build --preset windows-msvc-debug -- /m
& 'D:\App\CMake\bin\ctest.exe' `
  --preset windows-msvc-debug --output-on-failure

& 'D:\App\CMake\bin\cmake.exe' --build --preset windows-msvc-release -- /m
& 'D:\App\CMake\bin\ctest.exe' `
  --preset windows-msvc-release --output-on-failure
```

结果：NodeManager 专项通过；Debug 与 Release 全量均为 17/17 CTest 通过。
