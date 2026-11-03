// SPDX-License-Identifier: Apache-2.0
use crate::{
    error, flags::*, Address, AddressRange, OpCode, Result, SeqNum, SpaceId, SpaceTable, SpaceType,
    VarnodeData,
};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);
    };
}
id!(VarnodeId);
id!(OpId);
id!(BlockId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Varnode(VarnodeId),
    SpaceId(SpaceId),
    OpRef(OpId),
    Unset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Use {
    pub operation: OpId,
    pub slot: usize,
}

#[derive(Clone, Debug)]
pub struct Varnode {
    pub(crate) id: VarnodeId,
    pub(crate) data: VarnodeData,
    pub(crate) flags: VarnodeFlags,
    pub(crate) additional_flags: VarnodeAdditionalFlags,
    pub(crate) merge_group: i16,
    pub(crate) definition: Option<OpId>,
    pub(crate) uses: BTreeSet<Use>,
    pub(crate) consumed: u64,
    pub(crate) nonzero_mask: u64,
}
impl Varnode {
    pub fn id(&self) -> VarnodeId {
        self.id
    }
    pub fn data(&self) -> VarnodeData {
        self.data
    }
    pub fn flags(&self) -> VarnodeFlags {
        self.flags
    }
    pub fn additional_flags(&self) -> VarnodeAdditionalFlags {
        self.additional_flags
    }
    pub fn merge_group(&self) -> i16 {
        self.merge_group
    }
    pub fn definition(&self) -> Option<OpId> {
        self.definition
    }
    /// 同一个 op 的不同槽可重复使用同一个 varnode，必须保留重复使用关系。
    pub fn uses(&self) -> impl Iterator<Item = &Use> {
        self.uses.iter()
    }
    pub fn is_free(&self) -> bool {
        self.definition.is_none() && !self.flags.contains(VarnodeFlags::input)
    }
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
    pub fn nonzero_mask(&self) -> u64 {
        self.nonzero_mask
    }
}
#[derive(Clone, Debug)]
pub struct PcodeOp {
    pub(crate) id: OpId,
    pub(crate) opcode: OpCode,
    pub(crate) sequence: SeqNum,
    pub(crate) output: Option<VarnodeId>,
    pub(crate) inputs: Vec<Input>,
    pub(crate) parent: Option<BlockId>,
    pub(crate) flags: OpFlags,
    pub(crate) additional_flags: OpAdditionalFlags,
}
impl PcodeOp {
    pub fn id(&self) -> OpId {
        self.id
    }
    pub fn opcode(&self) -> OpCode {
        self.opcode
    }
    pub fn sequence(&self) -> SeqNum {
        self.sequence
    }
    pub fn output(&self) -> Option<VarnodeId> {
        self.output
    }
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }
    pub fn parent(&self) -> Option<BlockId> {
        self.parent
    }
    pub fn flags(&self) -> OpFlags {
        self.flags
    }
    pub fn additional_flags(&self) -> OpAdditionalFlags {
        self.additional_flags
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockEdge {
    pub other: BlockId,
    pub reverse_index: usize,
    pub flags: EdgeFlags,
}
#[derive(Clone, Debug)]
pub struct BlockBasic {
    pub(crate) id: BlockId,
    pub(crate) operations: Vec<OpId>,
    pub(crate) incoming: Vec<BlockEdge>,
    pub(crate) outgoing: Vec<BlockEdge>,
    pub(crate) ranges: Vec<AddressRange>,
    pub(crate) flags: BlockFlags,
}
impl BlockBasic {
    pub fn id(&self) -> BlockId {
        self.id
    }
    pub fn operations(&self) -> &[OpId] {
        &self.operations
    }
    pub fn incoming(&self) -> &[BlockEdge] {
        &self.incoming
    }
    pub fn outgoing(&self) -> &[BlockEdge] {
        &self.outgoing
    }
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }
    pub fn flags(&self) -> BlockFlags {
        self.flags
    }
    pub fn false_out(&self) -> Option<BlockId> {
        (self.outgoing.len() == 2).then(|| self.outgoing[0].other)
    }
    pub fn true_out(&self) -> Option<BlockId> {
        (self.outgoing.len() == 2).then(|| self.outgoing[1].other)
    }
}

/// SSA 节点按创建 ID 唯一，不能用 (space,offset,size) 合并不同写入。
/// 唯一的所有者负责同步 def-use 和双向 CFG 边，调用者没有可破坏链接的裸可变引用。
#[derive(Clone, Debug, Default)]
pub struct FunctionIr {
    pub(crate) varnodes: BTreeMap<VarnodeId, Varnode>,
    pub(crate) operations: BTreeMap<OpId, PcodeOp>,
    pub(crate) blocks: BTreeMap<BlockId, BlockBasic>,
    pub(crate) sequence_index: BTreeMap<(Address, u32), OpId>,
    next_varnode: u32,
    next_op: u32,
}
impl FunctionIr {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn varnodes(&self) -> impl Iterator<Item = &Varnode> {
        self.varnodes.values()
    }
    pub fn operations(&self) -> impl Iterator<Item = &PcodeOp> {
        self.operations.values()
    }
    pub fn blocks(&self) -> impl Iterator<Item = &BlockBasic> {
        self.blocks.values()
    }
    pub fn varnode(&self, id: VarnodeId) -> Result<&Varnode> {
        self.varnodes
            .get(&id)
            .ok_or_else(|| error(format!("unknown varnode {}", id.0)))
    }
    pub fn operation(&self, id: OpId) -> Result<&PcodeOp> {
        self.operations
            .get(&id)
            .ok_or_else(|| error(format!("unknown operation {}", id.0)))
    }
    pub fn block(&self, id: BlockId) -> Result<&BlockBasic> {
        self.blocks
            .get(&id)
            .ok_or_else(|| error(format!("unknown block {}", id.0)))
    }
    pub fn op_at(&self, sequence: SeqNum) -> Option<OpId> {
        self.sequence_index.get(&sequence.key()).copied()
    }
    pub fn op_by_time(&self, time: u32) -> Option<OpId> {
        self.operations
            .values()
            .find(|op| op.sequence.time == time)
            .map(|op| op.id)
    }
    /// 对应 VarnodeCompareLocDef，区别于 VarnodeData 的“大尺寸优先”排序。
    pub fn varnodes_by_location(&self) -> Vec<&Varnode> {
        let mut nodes: Vec<_> = self.varnodes.values().collect();
        nodes.sort_by_key(|vn| {
            let rank = if vn.flags.contains(VarnodeFlags::input) {
                0
            } else if vn.definition.is_some() {
                1
            } else {
                2
            };
            let seq = vn.definition.map(|id| self.operations[&id].sequence.key());
            (vn.data.address(), vn.data.size, rank, seq, vn.id)
        });
        nodes
    }
    pub fn find_input(&self, data: VarnodeData) -> Option<VarnodeId> {
        self.varnodes
            .values()
            .find(|vn| vn.data == data && vn.flags.contains(VarnodeFlags::input))
            .map(|vn| vn.id)
    }
    pub fn new_constant(
        &mut self,
        size: u32,
        value: u64,
        spaces: &SpaceTable,
    ) -> Result<VarnodeId> {
        if size == 0 {
            return Err(error("constant size is zero"));
        }
        let mask = if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        };
        self.new_varnode(
            VarnodeData::new(spaces.constant()?.id, value & mask, size),
            spaces,
        )
    }
    pub fn set_sequence(&mut self, id: OpId, sequence: SeqNum) -> Result<()> {
        let old = self.operation(id)?.sequence;
        if self
            .operations
            .values()
            .any(|op| op.id != id && op.sequence.time == sequence.time)
        {
            return Err(error("duplicate operation time"));
        }
        self.sequence_index.remove(&old.key());
        self.sequence_index.insert(sequence.key(), id);
        let op = self.operations.get_mut(&id).unwrap();
        op.sequence = SeqNum {
            order: old.order,
            ..sequence
        };
        Ok(())
    }
    pub fn new_varnode(&mut self, data: VarnodeData, spaces: &SpaceTable) -> Result<VarnodeId> {
        let id = VarnodeId(self.next_varnode);
        self.insert_varnode(id, data, spaces)?;
        Ok(id)
    }
    pub fn insert_varnode(
        &mut self,
        id: VarnodeId,
        data: VarnodeData,
        spaces: &SpaceTable,
    ) -> Result<()> {
        data.validate(spaces)?;
        if self.varnodes.contains_key(&id) {
            return Err(error("duplicate varnode ID"));
        }
        let next =
            id.0.checked_add(1)
                .ok_or_else(|| error("varnode ID exhausted"))?;
        let mut flags = VarnodeFlags::coverdirty;
        match spaces.get(data.space)?.kind {
            SpaceType::Constant => flags = VarnodeFlags::constant,
            SpaceType::Fspec | SpaceType::Iop => flags.set(VarnodeFlags::annotation),
            _ => (),
        }
        self.varnodes.insert(
            id,
            Varnode {
                id,
                data,
                flags,
                additional_flags: Default::default(),
                merge_group: 0,
                definition: None,
                uses: BTreeSet::new(),
                consumed: u64::MAX,
                nonzero_mask: if flags.contains(VarnodeFlags::constant) {
                    data.offset
                } else {
                    u64::MAX
                },
            },
        );
        self.next_varnode = self.next_varnode.max(next);
        Ok(())
    }
    pub fn set_input_varnode(&mut self, id: VarnodeId, value: bool) -> Result<()> {
        let vn = self.varnode(id)?;
        if value
            && (vn.definition.is_some()
                || vn
                    .flags
                    .intersects(VarnodeFlags::constant | VarnodeFlags::annotation))
        {
            return Err(error(
                "written/constant/annotation varnode cannot be a function input",
            ));
        }
        if value && self.find_input(vn.data).is_some_and(|other| other != id) {
            return Err(error("duplicate input storage"));
        }
        let vn = self.varnodes.get_mut(&id).unwrap();
        if value {
            vn.flags.set(VarnodeFlags::input | VarnodeFlags::insert);
        } else {
            vn.flags.remove(VarnodeFlags::input | VarnodeFlags::insert);
        }
        Ok(())
    }
    pub fn set_varnode_properties(
        &mut self,
        id: VarnodeId,
        flags: VarnodeFlags,
        extra: VarnodeAdditionalFlags,
        merge_group: i16,
    ) -> Result<()> {
        let old = self.varnode(id)?.flags;
        let managed = VarnodeFlags::input
            | VarnodeFlags::written
            | VarnodeFlags::constant
            | VarnodeFlags::annotation
            | VarnodeFlags::insert;
        if old.0 & managed.0 != flags.0 & managed.0 {
            return Err(error(
                "definition/input/storage flags are managed by the IR",
            ));
        }
        let vn = self.varnodes.get_mut(&id).unwrap();
        vn.flags = flags;
        vn.additional_flags = extra;
        vn.merge_group = merge_group;
        Ok(())
    }
    pub fn set_masks(&mut self, id: VarnodeId, consumed: u64, nonzero: u64) -> Result<()> {
        self.varnode(id)?;
        let vn = self.varnodes.get_mut(&id).unwrap();
        vn.consumed = consumed;
        vn.nonzero_mask = nonzero;
        Ok(())
    }
    pub fn new_op(&mut self, opcode: OpCode, sequence: SeqNum, input_count: usize) -> Result<OpId> {
        let id = OpId(self.next_op);
        self.insert_op(id, opcode, sequence, input_count)?;
        Ok(id)
    }
    pub fn insert_op(
        &mut self,
        id: OpId,
        opcode: OpCode,
        sequence: SeqNum,
        input_count: usize,
    ) -> Result<()> {
        if input_count > i32::MAX as usize
            || self.operations.contains_key(&id)
            || self.sequence_index.contains_key(&sequence.key())
        {
            return Err(error(
                "duplicate operation ID/sequence or invalid input count",
            ));
        }
        // uniq 在一个函数内唯一，<iop value=uniq> 才能无歧义地恢复 INDIRECT 引用。
        if self
            .operations
            .values()
            .any(|op| op.sequence.time == sequence.time)
        {
            return Err(error("duplicate operation time"));
        }
        let next =
            id.0.checked_add(1)
                .ok_or_else(|| error("operation ID exhausted"))?;
        self.operations.insert(
            id,
            PcodeOp {
                id,
                opcode,
                sequence,
                output: None,
                inputs: vec![Input::Unset; input_count],
                parent: None,
                flags: OpFlags::dead | opcode.default_flags(),
                additional_flags: Default::default(),
            },
        );
        self.sequence_index.insert(sequence.key(), id);
        self.next_op = self.next_op.max(next);
        Ok(())
    }
    fn check_input(&self, input: Input) -> Result<()> {
        match input {
            Input::Varnode(id) => {
                self.varnode(id)?;
            }
            Input::OpRef(id) => {
                self.operation(id)?;
            }
            _ => (),
        }
        Ok(())
    }
    pub fn set_inputs(&mut self, id: OpId, inputs: Vec<Input>) -> Result<()> {
        self.operation(id)?;
        for input in &inputs {
            self.check_input(*input)?;
        }
        let old = self.operation(id)?.inputs.clone();
        for (slot, input) in old.iter().enumerate() {
            if let Input::Varnode(vn) = input {
                self.varnodes.get_mut(vn).unwrap().uses.remove(&Use {
                    operation: id,
                    slot,
                });
            }
        }
        for (slot, input) in inputs.iter().enumerate() {
            if let Input::Varnode(vn) = input {
                self.varnodes.get_mut(vn).unwrap().uses.insert(Use {
                    operation: id,
                    slot,
                });
            }
        }
        self.operations.get_mut(&id).unwrap().inputs = inputs;
        Ok(())
    }
    pub fn set_input(&mut self, id: OpId, slot: usize, input: Input) -> Result<()> {
        let mut inputs = self.operation(id)?.inputs.clone();
        *inputs
            .get_mut(slot)
            .ok_or_else(|| error("input slot out of bounds"))? = input;
        self.set_inputs(id, inputs)
    }
    pub fn insert_input(&mut self, id: OpId, slot: usize, input: Input) -> Result<()> {
        let mut inputs = self.operation(id)?.inputs.clone();
        if slot > inputs.len() {
            return Err(error("input slot out of bounds"));
        }
        inputs.insert(slot, input);
        self.set_inputs(id, inputs)
    }
    pub fn remove_input(&mut self, id: OpId, slot: usize) -> Result<Input> {
        let mut inputs = self.operation(id)?.inputs.clone();
        if slot >= inputs.len() {
            return Err(error("input slot out of bounds"));
        }
        let old = inputs.remove(slot);
        self.set_inputs(id, inputs)?;
        Ok(old)
    }
    pub fn set_output(&mut self, op: OpId, output: Option<VarnodeId>) -> Result<()> {
        let old = self.operation(op)?.output;
        if old == output {
            return Ok(());
        }
        if let Some(id) = output {
            let vn = self.varnode(id)?;
            if vn.definition.is_some()
                || vn.flags.0
                    & (VarnodeFlags::input | VarnodeFlags::constant | VarnodeFlags::annotation).0
                    != 0
            {
                return Err(error("SSA output must be a free, writable varnode"));
            }
        }
        if let Some(id) = old {
            let vn = self.varnodes.get_mut(&id).unwrap();
            vn.definition = None;
            vn.flags
                .remove(VarnodeFlags::written | VarnodeFlags::insert);
        }
        if let Some(id) = output {
            let vn = self.varnodes.get_mut(&id).unwrap();
            vn.definition = Some(op);
            vn.flags.set(VarnodeFlags::written | VarnodeFlags::insert);
        }
        self.operations.get_mut(&op).unwrap().output = output;
        Ok(())
    }
    pub fn set_opcode(&mut self, id: OpId, opcode: OpCode) -> Result<()> {
        self.operation(id)?;
        let op = self.operations.get_mut(&id).unwrap();
        op.flags.0 = (op.flags.0 & !OpCode::TYPE_FLAGS) | opcode.default_flags().0;
        op.opcode = opcode;
        Ok(())
    }
    pub fn set_op_properties(
        &mut self,
        id: OpId,
        flags: OpFlags,
        extra: OpAdditionalFlags,
    ) -> Result<()> {
        let op = self.operation(id)?;
        if flags.contains(OpFlags::dead) != op.parent.is_none() {
            return Err(error("dead flag must agree with block membership"));
        }
        let op = self.operations.get_mut(&id).unwrap();
        op.flags = flags;
        op.additional_flags = extra;
        Ok(())
    }
    pub fn replace_all_uses(&mut self, old: VarnodeId, replacement: VarnodeId) -> Result<()> {
        self.varnode(replacement)?;
        let uses: Vec<_> = self.varnode(old)?.uses.iter().copied().collect();
        for usage in uses {
            self.set_input(usage.operation, usage.slot, Input::Varnode(replacement))?;
        }
        Ok(())
    }
    pub fn insert_block(&mut self, id: BlockId) -> Result<()> {
        if id.0 > i32::MAX as u32 || self.blocks.contains_key(&id) {
            return Err(error("invalid or duplicate block ID"));
        }
        self.blocks.insert(
            id,
            BlockBasic {
                id,
                operations: vec![],
                incoming: vec![],
                outgoing: vec![],
                ranges: vec![],
                flags: Default::default(),
            },
        );
        Ok(())
    }
    pub fn set_ranges(&mut self, id: BlockId, mut ranges: Vec<AddressRange>) -> Result<()> {
        self.block(id)?;
        if ranges.iter().any(|r| r.first > r.last) {
            return Err(error("reversed block range"));
        }
        ranges.sort();
        let mut merged: Vec<AddressRange> = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut() {
                if last.space == range.space && range.first <= last.last.saturating_add(1) {
                    last.last = last.last.max(range.last);
                    continue;
                }
            }
            merged.push(range);
        }
        self.blocks.get_mut(&id).unwrap().ranges = merged;
        Ok(())
    }
    pub fn set_block_flags(&mut self, id: BlockId, flags: BlockFlags) -> Result<()> {
        self.block(id)?;
        self.blocks.get_mut(&id).unwrap().flags = flags;
        Ok(())
    }
    fn renumber(&mut self, block: BlockId) {
        for (order, id) in self.blocks[&block].operations.iter().enumerate() {
            self.operations.get_mut(id).unwrap().sequence.order = order as u32;
        }
    }
    pub fn uninsert(&mut self, id: OpId) -> Result<()> {
        if let Some(parent) = self.operation(id)?.parent {
            self.blocks
                .get_mut(&parent)
                .unwrap()
                .operations
                .retain(|op| *op != id);
            let op = self.operations.get_mut(&id).unwrap();
            op.parent = None;
            op.flags.set(OpFlags::dead);
            self.renumber(parent);
        }
        Ok(())
    }
    pub fn insert_at(&mut self, id: OpId, block: BlockId, position: usize) -> Result<()> {
        self.operation(id)?;
        if position > self.block(block)?.operations.len() {
            return Err(error("block insertion position out of bounds"));
        }
        let old_position = self
            .block(block)?
            .operations
            .iter()
            .position(|op| *op == id);
        self.uninsert(id)?;
        let position = position - usize::from(old_position.is_some_and(|old| old < position));
        self.blocks
            .get_mut(&block)
            .unwrap()
            .operations
            .insert(position, id);
        let op = self.operations.get_mut(&id).unwrap();
        op.parent = Some(block);
        op.flags.remove(OpFlags::dead);
        self.renumber(block);
        Ok(())
    }
    pub fn destroy_op(&mut self, id: OpId) -> Result<()> {
        self.operation(id)?;
        if self
            .operations
            .values()
            .any(|op| op.inputs.contains(&Input::OpRef(id)))
        {
            return Err(error("operation is still referenced by INDIRECT"));
        }
        self.set_output(id, None)?;
        self.set_inputs(id, vec![])?;
        self.uninsert(id)?;
        let op = self.operations.remove(&id).unwrap();
        self.sequence_index.remove(&op.sequence.key());
        Ok(())
    }
    pub fn destroy_varnode(&mut self, id: VarnodeId) -> Result<()> {
        let vn = self.varnode(id)?;
        if vn.definition.is_some() || !vn.uses.is_empty() {
            return Err(error("varnode still participates in dataflow"));
        }
        self.varnodes.remove(&id);
        Ok(())
    }
    /// 保留平行边、自环及输入边顺序；MULTIEQUAL 的输入槽就是入边槽。
    pub fn add_edge(&mut self, from: BlockId, to: BlockId, flags: EdgeFlags) -> Result<()> {
        let outgoing_index = self.block(from)?.outgoing.len();
        let incoming_index = self.block(to)?.incoming.len();
        self.blocks
            .get_mut(&from)
            .unwrap()
            .outgoing
            .push(BlockEdge {
                other: to,
                reverse_index: incoming_index,
                flags,
            });
        self.blocks.get_mut(&to).unwrap().incoming.push(BlockEdge {
            other: from,
            reverse_index: outgoing_index,
            flags,
        });
        Ok(())
    }
    pub fn remove_edge(&mut self, from: BlockId, outgoing_index: usize) -> Result<()> {
        let edge = *self
            .block(from)?
            .outgoing
            .get(outgoing_index)
            .ok_or_else(|| error("edge index out of bounds"))?;
        let phi: Vec<_> = self
            .block(edge.other)?
            .operations
            .iter()
            .copied()
            .filter(|id| self.operations[id].opcode == OpCode::MULTIEQUAL)
            .collect();
        if phi
            .iter()
            .any(|id| self.operations[id].inputs.len() != self.blocks[&edge.other].incoming.len())
        {
            return Err(error("phi arity does not match incoming edges"));
        }
        for id in phi {
            self.remove_input(id, edge.reverse_index)?;
        }
        self.blocks
            .get_mut(&from)
            .unwrap()
            .outgoing
            .remove(outgoing_index);
        self.blocks
            .get_mut(&edge.other)
            .unwrap()
            .incoming
            .remove(edge.reverse_index);
        // 先调整索引值再解引用，防止删除自环/平行自环后旧反向索引越界。
        for block in self.blocks.values_mut() {
            for e in &mut block.outgoing {
                if e.other == edge.other && e.reverse_index > edge.reverse_index {
                    e.reverse_index -= 1;
                }
            }
            for e in &mut block.incoming {
                if e.other == from && e.reverse_index > outgoing_index {
                    e.reverse_index -= 1;
                }
            }
        }
        Ok(())
    }
    pub fn set_edge_flags(&mut self, from: BlockId, slot: usize, flags: EdgeFlags) -> Result<()> {
        let edge = *self
            .block(from)?
            .outgoing
            .get(slot)
            .ok_or_else(|| error("edge slot out of bounds"))?;
        self.blocks.get_mut(&from).unwrap().outgoing[slot].flags = flags;
        self.blocks.get_mut(&edge.other).unwrap().incoming[edge.reverse_index].flags = flags;
        Ok(())
    }
    /// 给已有 phi 的基本块添加前驱时，必须同时为每个 phi 提供新增输入。
    pub fn add_edge_with_phi(
        &mut self,
        from: BlockId,
        to: BlockId,
        flags: EdgeFlags,
        values: &[(OpId, Input)],
    ) -> Result<()> {
        self.block(from)?;
        let block = self.block(to)?;
        let phi: Vec<_> = block
            .operations
            .iter()
            .copied()
            .filter(|id| self.operations[id].opcode == OpCode::MULTIEQUAL)
            .collect();
        if phi.len() != values.len()
            || values
                .iter()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
                .len()
                != values.len()
        {
            return Err(error("must provide exactly one input per phi"));
        }
        for id in &phi {
            if self.operations[id].inputs.len() != block.incoming.len() {
                return Err(error("existing phi arity mismatch"));
            }
            let input = values
                .iter()
                .find(|(op, _)| op == id)
                .ok_or_else(|| error("missing phi input"))?
                .1;
            self.check_input(input)?;
        }
        for (id, input) in values {
            let len = self.operation(*id)?.inputs.len();
            self.insert_input(*id, len, *input)?;
        }
        self.add_edge(from, to, flags)
    }
    pub fn destroy_block(&mut self, id: BlockId) -> Result<()> {
        let block = self.block(id)?;
        if !block.operations.is_empty() || !block.incoming.is_empty() || !block.outgoing.is_empty()
        {
            return Err(error("block is still connected"));
        }
        self.blocks.remove(&id);
        Ok(())
    }
    pub fn swap_out_edges(&mut self, block: BlockId) -> Result<()> {
        if self.block(block)?.outgoing.len() != 2 {
            return Err(error("conditional block must have two outgoing edges"));
        }
        self.blocks.get_mut(&block).unwrap().outgoing.swap(0, 1);
        let edges = self.blocks[&block].outgoing.clone();
        for (slot, edge) in edges.iter().enumerate() {
            self.blocks.get_mut(&edge.other).unwrap().incoming[edge.reverse_index].reverse_index =
                slot;
        }
        Ok(())
    }
    pub fn validate(&self, spaces: &SpaceTable) -> Result<()> {
        for vn in self.varnodes.values() {
            vn.data.validate(spaces)?;
            if vn.flags.contains(VarnodeFlags::written) != vn.definition.is_some() {
                return Err(error("written flag mismatch"));
            }
            if let Some(op) = vn.definition {
                if self.operation(op)?.output != Some(vn.id) {
                    return Err(error("broken defining operation"));
                }
            }
            for usage in &vn.uses {
                if self.operation(usage.operation)?.inputs.get(usage.slot)
                    != Some(&Input::Varnode(vn.id))
                {
                    return Err(error("broken use link"));
                }
            }
        }
        for op in self.operations.values() {
            spaces.validate_address(op.sequence.address)?;
            if self.sequence_index.get(&op.sequence.key()) != Some(&op.id) {
                return Err(error("broken sequence index"));
            }
            if let Some(vn) = op.output {
                if self.varnode(vn)?.definition != Some(op.id) {
                    return Err(error("broken output link"));
                }
            }
            for (slot, input) in op.inputs.iter().enumerate() {
                match input {
                    Input::Varnode(vn) => {
                        if !self.varnode(*vn)?.uses.contains(&Use {
                            operation: op.id,
                            slot,
                        }) {
                            return Err(error("missing use link"));
                        }
                    }
                    Input::SpaceId(id) => {
                        spaces.get(*id)?;
                        if slot != 0 || !matches!(op.opcode, OpCode::LOAD | OpCode::STORE) {
                            return Err(error("invalid spaceid operand"));
                        }
                    }
                    Input::OpRef(id) => {
                        self.operation(*id)?;
                        if slot != 1 || op.opcode != OpCode::INDIRECT {
                            return Err(error("invalid iop operand"));
                        }
                    }
                    Input::Unset => (),
                }
            }
            if op.flags.contains(OpFlags::dead) != op.parent.is_none() {
                return Err(error("operation liveness mismatch"));
            }
            if let Some(block) = op.parent {
                if self
                    .block(block)?
                    .operations
                    .get(op.sequence.order as usize)
                    != Some(&op.id)
                {
                    return Err(error("invalid block operation order"));
                }
                if op.opcode == OpCode::MULTIEQUAL
                    && op.inputs.len() != self.block(block)?.incoming.len()
                {
                    return Err(error("MULTIEQUAL inputs must match predecessor slots"));
                }
            }
        }
        for block in self.blocks.values() {
            for id in &block.operations {
                if self.operation(*id)?.parent != Some(block.id) {
                    return Err(error("broken block membership"));
                }
            }
            for range in &block.ranges {
                spaces.get(range.space)?;
            }
            for (slot, e) in block.outgoing.iter().enumerate() {
                let reverse = self
                    .block(e.other)?
                    .incoming
                    .get(e.reverse_index)
                    .ok_or_else(|| error("missing reverse edge"))?;
                if reverse.other != block.id
                    || reverse.reverse_index != slot
                    || reverse.flags != e.flags
                {
                    return Err(error("inconsistent reverse edge"));
                }
            }
            for (slot, e) in block.incoming.iter().enumerate() {
                let reverse = self
                    .block(e.other)?
                    .outgoing
                    .get(e.reverse_index)
                    .ok_or_else(|| error("missing outgoing edge"))?;
                if reverse.other != block.id
                    || reverse.reverse_index != slot
                    || reverse.flags != e.flags
                {
                    return Err(error("inconsistent incoming edge"));
                }
            }
        }
        Ok(())
    }
}
