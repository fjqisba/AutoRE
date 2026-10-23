// SPDX-License-Identifier: Apache-2.0
//! Ghidra P-code 的 Rust 数据模型；opcode 数字及交换格式以仓库内 Ghidra 源码为基准。
//! 本 crate 不运行 Java，不通过 FFI 代理 C++，也不将 P-code 改写为 LLVM IR。
#![forbid(unsafe_code)]

pub mod address;
pub mod flags;
pub mod graph;
pub mod marshal;
pub mod opcode;
pub mod raw;
pub mod wire;

pub use address::{
    AddrSpace, Address, AddressRange, Endian, JoinRecord, SeqNum, SpaceId, SpaceTable, SpaceType,
    VarnodeData,
};
pub use graph::{
    BlockBasic, BlockEdge, BlockId, FunctionIr, Input, OpId, PcodeOp, Use, Varnode, VarnodeId,
};
pub use opcode::OpCode;
pub use raw::{PcodeCollector, PcodeEmit, PcodeOpRaw, RawOperand};
pub use wire::Instruction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn error(message: impl Into<String>) -> Error {
    Error(message.into())
}
