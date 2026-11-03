---
name: ue-reverse-engineering
description: 使用 Dumper-7 与 FModel/CUE4Parse 分析 Unreal Engine 4/5 游戏的反射结构、SDK 偏移与 pak 资产；包含运行时 SDK dump、加密 pak 的 AES 密钥定位（Frida 动态挂钩 + 静态回溯）、资产与贴图批量导出。适用于已获授权的单机副本或自有构建，不用于联机对抗或绕过反作弊。
metadata:
  short-description: UE4/5 反射 dump、pak 解密与资产导出
---

# UE4/UE5 游戏逆向

目标是把一个 UE 游戏拆成三样可复核的东西：**反射结构（类/字段/函数偏移）**、**资产（pak 内容）**、**可查看的贴图/预览**。三者互相验证：SDK 的偏移能回填 IDA，pak 里的资产能对照类结构。

工具优先复用项目 `tools/Dumper-7/`、`tools/FModel/`；位置不同时按用户提供路径确定，不自动重装或改全局配置。

## 侦察

先确定引擎版本和打包形态，后面所有判断都依赖它。

- 版本：搜索宽字符串 `++UE4+Release-`、`++UE5+Release-`、`UnrealEngine4`。UE4.27 与 UE5 的对象布局差别很大。

## Dumper-7（运行时 dump 反射）

### 配置

`Dumper-7.ini` 放在游戏 exe 同目录（单游戏）或输出根目录（全局）：

```ini
[Settings]
SleepTimeout=5
SDKGenerationPath=<输出目录>
LogFilePath=<输出目录>/dumper.log
ShouldAutoUnload=1
```

### 产物与校验

| 产物 | 用途 |
|---|---|
| `CppSDK/SDK/*.hpp` | 类、字段偏移、函数签名 |
| `Dumpspace/*.json` | 机器可读的类/枚举/函数/偏移清单 |
| `Mappings/*.usmap` | FModel/CUE4Parse 解析 unversioned property |
| `IDAMappings/*.idmap` | 把函数名导回 IDA |
| `GObjects-Dump.txt` | 运行时对象清单 |

校验方式：取 `OffsetsInfo.json` 里的 RVA 加上 ImageBase，在 IDA 中查 xref。`GObjects` 正常应有上千处引用，`ProcessEvent` 应是函数起点且有大量调用者；引用数为 0 说明基址或版本判断有误。

##  pak 解密（AES 密钥）

### 先判断“是否真的加密”

读取文件尾部 `FPakInfo`：magic `0x5A6F12E1`、version、indexOffset、indexSize、hash，之后是字段 `bEncryptedIndex`。**不要只信文件里的字段顺序**——定制引擎可能删掉 GUID 或调整顺序；以运行时解析结果为准（见下）。

### 正确路线 A · 动态挂钩（首选）

1. 想办法注入进程使得可以挂钩函数。
2. 找候选解密函数：
   - AES-NI：搜索 `66 0F 38 DC`（AESDEC）、`66 0F 3A DF`（AESKEYGENASSIST）；
   - 查表实现：`Te0[0] = 0xC66363A5`、`Td0[0] = 0x51F4A750` 的引用；
   - 逐块解密的调用形态：`(ctx, rounds, src, dst)`，`src` 每次 `+0x10`，`rounds=14` 即 AES-256。
3. **挂钩“密钥扩展”而不是解密本体**：形态通常是 `(ctx, key, bits)`，`bits=256`，第二个参数就是 32 字节原始密钥，直接 `readByteArray(32)`。
4. 离线用 AES-256-ECB 解索引首块验证 oracle。

注意：UE 的 `FAES` 不一定被使用。定制引擎常自实现一套 AES，`FAES` 的 AES-NI/查表函数在启动阶段可能一次都不被调用——周边出现 OpenSSL 字符串也不代表 pak 用了 OpenSSL。

### 正确路线 B · 静态回溯

在 IDA 里搜 magic 立即数 `0x5A6F12E1` 的引用，定位 `FPakInfo::Serialize`，再向上找读取索引后的调用；解密函数拿到 `(buffer, size)`，密钥要么是全局 `FAESKey`，要么由上游函数传入。适合只需要偏移、不方便附加进程的场景。
