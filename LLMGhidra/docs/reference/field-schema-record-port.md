# Field、Schema 与 Record C++ 迁移证据

## 已实现映射

| Java 基线 | C++ 目标 | 当前覆盖 |
|---|---|---|
| `Field`、`PrimitiveField`、四个整数 Field、`BooleanField` | `field.hpp`、`field.cpp` | 类型编码、大端读写、null state、窄化、比较、stored compare、hash、min/max、格式化 |
| `BinaryField`、`StringField` | `field.hpp`、`field.cpp` | 长度前缀、null value、truncate、无符号二进制排序、Java UTF-16 字符串排序/hash、UTF-8 replacement decode |
| `FixedField`、`FixedField10` | `field.hpp`、`field.cpp` | unsigned 80-bit 排序、固定长度、null state、hash、min/max |
| `IndexField`、`LegacyIndexField` | `field.hpp`、`field.cpp` | `PPPPFFFF`/legacy 编码、64-byte key truncation、组合比较、stored compare、fixed binary form |
| `BinaryCodedField`、`BinaryDataBuffer` | `binary_coded_field.hpp`、`binary_coded_field.cpp` | 9 种 tag、标量/数组、null 数组、String 数组、Java canonical NaN bits |
| `Schema` | `schema.hpp`、`schema.cpp` | 字段和扩展编码、尾分号 names、sparse 校验、key node 选择、深拷贝 |
| `DBRecord`、`SparseRecord` | `record.hpp`、`record.cpp` | 普通/sparse 布局、dirty、长度缓存、clone/compare/hash、失败读入原子性 |

基线源锚点均位于 `Ghidra/Framework/DB/src/main/java/db/` 下的同名类。

## 自动化测试

- `field_compatibility_tests.cpp`：精确编码、类型、比较、hash、truncate、Unicode 和 IndexField。
- `binary_coded_field_tests.cpp`：所有 tag 的精确字节与往返。
- `schema_record_tests.cpp`：schema/node 选择、sparse extension、Record 生命周期、精确布局和损坏输入。
- `field_record_tests.cpp`：Field → Schema → Record 的组合回归。

## 尚未解除 REVIEW_REQUIRED 的原因

- Java 21 Oracle 构建尚未恢复，缺少 Java/C++ 同输入随机差分。
- 尚未生成基线 Java 字节 fixture 与双向数据库 cross-open 证据。
- UTF-8 malformed sequence 的 replacement 分组仍需用 Oracle 穷举确认。
- 上游 `Framework/DB` 完整 Field/Schema/Record 测试尚未逐测试登记迁移。

因此这些台账项已有 C++ 目标和本地证据，但状态仍保持 `REVIEW_REQUIRED`。
