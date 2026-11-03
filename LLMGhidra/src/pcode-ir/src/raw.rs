// SPDX-License-Identifier: Apache-2.0
use crate::{error, Address, OpCode, Result, SeqNum, SpaceId, SpaceTable, VarnodeData};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawOperand {
    Varnode(VarnodeData),
    /// LOAD/STORE input[0]：线上是 <spaceid>，不是可计算的常量值。
    SpaceId(SpaceId),
}
#[derive(Clone, Debug)]
pub struct PcodeOpRaw {
    pub opcode: OpCode,
    pub sequence: SeqNum,
    pub output: Option<VarnodeData>,
    pub inputs: Vec<RawOperand>,
}
impl PcodeOpRaw {
    pub fn new(
        opcode: OpCode,
        sequence: SeqNum,
        output: Option<VarnodeData>,
        inputs: Vec<RawOperand>,
    ) -> Self {
        Self {
            opcode,
            sequence,
            output,
            inputs,
        }
    }
    /// 只检查 IR 结构和特殊引用，不强加 raw 指令参数数量到优化后的 CALL/RETURN。
    pub fn validate(&self, spaces: &SpaceTable) -> Result<()> {
        spaces.validate_address(self.sequence.address)?;
        if let Some(out) = self.output {
            out.validate(spaces)?;
        }
        if matches!(self.opcode, OpCode::LOAD | OpCode::STORE)
            && !matches!(self.inputs.first(), Some(RawOperand::SpaceId(_)))
        {
            return Err(error(
                "LOAD/STORE input[0] must be an address-space reference",
            ));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            match *input {
                RawOperand::Varnode(vn) => vn.validate(spaces)?,
                RawOperand::SpaceId(id) => {
                    spaces.get(id)?;
                    if index != 0 || !matches!(self.opcode, OpCode::LOAD | OpCode::STORE) {
                        return Err(error("spaceid is only valid as LOAD/STORE input[0]"));
                    }
                }
            }
        }
        Ok(())
    }
    /// BRANCH/CBRANCH 的 const 目标是相对当前 p-code 操作的位移，不能当机器地址。
    pub fn relative_branch_target(
        &self,
        index: usize,
        operation_count: usize,
        spaces: &SpaceTable,
    ) -> Result<Option<usize>> {
        if !matches!(self.opcode, OpCode::BRANCH | OpCode::CBRANCH) {
            return Ok(None);
        }
        let Some(RawOperand::Varnode(target)) = self.inputs.first() else {
            return Ok(None);
        };
        if spaces.get(target.space)?.kind != crate::SpaceType::Constant {
            return Ok(None);
        }
        if index > i32::MAX as usize || operation_count > i32::MAX as usize {
            return Err(error("instruction p-code count exceeds intm"));
        }
        // EmulatePcodeCache 先截断为 uintm (32 bit)，加 current_op 后转回 intm。
        let destination = (index as u32).wrapping_add(target.offset as u32) as i32 as i128;
        // 跳到 p-code 列表尾后一个位置表示结束当前机器指令。
        if destination < 0 || destination > operation_count as i128 {
            return Err(error("relative p-code branch escapes instruction"));
        }
        Ok(Some(destination as usize))
    }
    pub fn display(&self, spaces: &SpaceTable) -> Result<String> {
        let vn = |v: VarnodeData| -> Result<String> {
            Ok(format!(
                "({},{:#x},{})",
                spaces.get(v.space)?.name,
                v.offset,
                v.size
            ))
        };
        let mut out = String::new();
        if let Some(v) = self.output {
            out.push_str(&vn(v)?);
            out.push_str(" = ");
        }
        out.push_str(self.opcode.mnemonic());
        for (i, input) in self.inputs.iter().enumerate() {
            out.push_str(if i == 0 { " " } else { ", " });
            out.push_str(&match input {
                RawOperand::Varnode(v) => vn(*v)?,
                RawOperand::SpaceId(s) => format!("<{}>", spaces.get(*s)?.name),
            });
        }
        Ok(out)
    }
}

/// 原生 SLEIGH 适配层可向该接口直接提交操作，调用方负责为机器指令内各 op 分配 time。
pub trait PcodeEmit {
    fn dump(
        &mut self,
        address: Address,
        opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[RawOperand],
    ) -> Result<()>;
}
#[derive(Default)]
pub struct PcodeCollector {
    pub operations: Vec<PcodeOpRaw>,
    next_time: u32,
}
impl PcodeEmit for PcodeCollector {
    fn dump(
        &mut self,
        address: Address,
        opcode: OpCode,
        output: Option<VarnodeData>,
        inputs: &[RawOperand],
    ) -> Result<()> {
        let next = self
            .next_time
            .checked_add(1)
            .ok_or_else(|| error("sequence time exhausted"))?;
        self.operations.push(PcodeOpRaw::new(
            opcode,
            SeqNum::new(address, self.next_time),
            output,
            inputs.to_vec(),
        ));
        self.next_time = next;
        Ok(())
    }
}
