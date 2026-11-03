# 第三方组件

本项目通过固定版本源码及系统工具使用以下组件。这里只记录来源；实际分发二进制时还需携带对应版本的许可证和必要声明。

| 组件 | 来源与版本入口 | 许可证入口 |
|---|---|---|
| Remill | `toolchains/versions.lock.json`；[上游](https://github.com/lifting-bits/remill) | 源码 `third_party/remill/LICENSE` |
| LLVM / Clang | 本机外部工具链；版本见锁定清单 | 对应发行物 LICENSE.TXT / NOTICE |
| Intel XED / mbuild | Remill 依赖构建，commit 写入清单 | 对应依赖源码 LICENSE |
| gflags / glog / googletest | Remill 依赖构建，commit 写入清单 | 对应依赖源码 COPYING / LICENSE |
| Rust crates | Cargo.toml 与 Cargo.lock | 各 crate 发布包许可证 |
| Z3 | 本机现有安装；[上游](https://github.com/Z3Prover/z3) | 对应安装包 LICENSE |

`toolchains/patches/remill-x86-windows.patch` 是本项目对固定上游 revision 的构建配置修改。不要将上游源码、构建产物或现有工具的许可证改写为 NeREUS 自有许可证。
