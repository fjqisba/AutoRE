// SPDX-License-Identifier: Apache-2.0
//! 自动基础索引与有预算、可取消的局部分析，共享本地查询接口。
pub mod elf;
pub mod engine;
pub mod index;
pub mod pool;
pub mod protocol;

pub type Result<T> = std::result::Result<T, String>;
pub use elf::{ElfImage, Function, Segment};
pub use engine::{Analysis, Engine, Instruction, Limits};
pub use pool::{Cancellation, WorkerPool};
