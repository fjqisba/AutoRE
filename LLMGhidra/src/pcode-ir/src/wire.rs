// SPDX-License-Identifier: Apache-2.0
//! raw <op> 与 Funcdata::encodeTree 的 <ast> 是不同协议，不能混用。
//! 本模块对应 translate.cc / op.cc / varnode.cc / funcdata.cc / block.cc。
use crate::{
    error,
    flags::*,
    graph::BlockEdge,
    marshal::{self, attribute as a, element as e, Element, Value as V},
    Address, AddressRange, BlockId, FunctionIr, Input, OpCode, OpId, PcodeOpRaw, RawOperand,
    Result, SeqNum, SpaceTable, SpaceType, VarnodeData, VarnodeId,
};
use std::collections::{BTreeMap, BTreeSet};

fn u32_value(value: &V) -> Result<u32> {
    u32::try_from(value.unsigned()?).map_err(|_| error("value exceeds uint4"))
}
fn index(value: &V) -> Result<u32> {
    let n = value.signed()?;
    if !(0..=i32::MAX as i64).contains(&n) {
        return Err(error("invalid nonnegative int4"));
    }
    Ok(n as u32)
}
fn leaf(node: &Element) -> Result<()> {
    if node.children.is_empty() {
        Ok(())
    } else {
        Err(error("unexpected child element"))
    }
}

fn encode_storage(
    tag: u16,
    data: VarnodeData,
    with_size: bool,
    spaces: &SpaceTable,
) -> Result<Element> {
    let mut node = Element::new(tag).with(a::SPACE, V::Space(data.space));
    if spaces.get(data.space)?.kind == SpaceType::Join {
        let record = spaces.join(data.offset)?;
        for (i, piece) in record.pieces.iter().enumerate() {
            node.attributes.push((
                a::PIECE + i as u16,
                V::Text(format!(
                    "{}:0x{:x}:{}",
                    spaces.get(piece.space)?.name,
                    piece.offset,
                    piece.size
                )),
            ));
        }
        if record.pieces.len() == 1 {
            node.attributes
                .push((a::LOGICALSIZE, V::Unsigned(record.unified.size as u64)));
        }
    } else {
        node.attributes.push((a::OFFSET, V::Unsigned(data.offset)));
        if with_size {
            node.attributes.push((a::SIZE, V::Signed(data.size as i64)));
        }
    }
    Ok(node)
}
fn decode_storage(node: &Element, with_size: bool, spaces: &mut SpaceTable) -> Result<VarnodeData> {
    if !matches!(node.id, e::ADDR | e::SEQNUM | e::VARNODE | e::REGISTER) {
        return Err(error("expected storage element"));
    }
    leaf(node)?;
    if let Some(name) = node.get(a::NAME) {
        return spaces.register(name.text()?);
    }
    let space = node.require(a::SPACE)?.space(spaces)?;
    if spaces.get(space)?.kind == SpaceType::Join {
        let mut pieces = BTreeMap::new();
        for (id, value) in &node.attributes {
            if !(a::PIECE..a::PIECE + 64).contains(id) {
                continue;
            }
            let text = value.text()?;
            let piece = if text.contains(':') {
                let fields: Vec<_> = text.split(':').collect();
                if fields.len() != 3 {
                    return Err(error("invalid join piece"));
                }
                VarnodeData::new(
                    spaces.named(fields[0])?.id,
                    marshal::parse_unsigned(fields[1])?,
                    u32::try_from(marshal::parse_unsigned(fields[2])?)
                        .map_err(|_| error("piece size overflow"))?,
                )
            } else {
                spaces.register(text)?
            };
            if pieces.insert(id - a::PIECE, piece).is_some() {
                return Err(error("duplicate join piece"));
            }
        }
        if pieces.keys().enumerate().any(|(i, k)| i != *k as usize) {
            return Err(error("missing join piece"));
        }
        let logical_size = node
            .get(a::LOGICALSIZE)
            .map(u32_value)
            .transpose()?
            .unwrap_or(0);
        return spaces.find_add_join(pieces.into_values().collect(), logical_size);
    }
    let offset = node.require(a::OFFSET)?.unsigned()?;
    let size = if with_size {
        index(node.require(a::SIZE)?)?
    } else {
        0
    };
    let data = VarnodeData::new(space, offset, size);
    if with_size {
        data.validate(spaces)?;
    }
    Ok(data)
}
pub fn encode_sequence(sequence: SeqNum, spaces: &SpaceTable) -> Result<Element> {
    let (space, offset) = sequence.address.parts()?;
    Ok(
        encode_storage(e::SEQNUM, VarnodeData::new(space, offset, 0), false, spaces)?
            .with(a::UNIQ, V::Unsigned(sequence.time as u64)),
    )
}
pub fn decode_sequence(node: &Element, spaces: &mut SpaceTable) -> Result<SeqNum> {
    node.expect(e::SEQNUM)?;
    let data = decode_storage(node, false, spaces)?;
    let time = node
        .get(a::UNIQ)
        .map(u32_value)
        .transpose()?
        .unwrap_or(u32::MAX);
    Ok(SeqNum::new(data.address(), time))
}

/// raw 操作的机器地址与 seqnum 由指令容器提供，不在 <op> 内重复编码。
pub fn encode_raw(op: &PcodeOpRaw, spaces: &SpaceTable) -> Result<Element> {
    op.validate(spaces)?;
    let mut node = Element::new(e::OP)
        .with(a::CODE, V::Signed(op.opcode.number() as i64))
        .with(a::SIZE, V::Signed(op.inputs.len() as i64));
    node.children.push(match op.output {
        Some(v) => encode_storage(e::ADDR, v, true, spaces)?,
        None => Element::new(e::VOID),
    });
    for input in &op.inputs {
        node.children.push(match input {
            RawOperand::Varnode(v) => encode_storage(e::ADDR, *v, true, spaces)?,
            RawOperand::SpaceId(id) => Element::new(e::SPACEID).with(a::NAME, V::Space(*id)),
        });
    }
    Ok(node)
}
pub fn decode_raw(node: &Element, sequence: SeqNum, spaces: &mut SpaceTable) -> Result<PcodeOpRaw> {
    // 失败的导入不能留下半个 join 分配表。
    let mut working = spaces.clone();
    node.expect(e::OP)?;
    let opcode = OpCode::try_from(u32_value(node.require(a::CODE)?)?)?;
    let size = index(node.require(a::SIZE)?)? as usize;
    if node.children.len() != size + 1 {
        return Err(error("raw op input count mismatch"));
    }
    let out = &node.children[0];
    let output = if out.id == e::VOID {
        leaf(out)?;
        None
    } else {
        Some(decode_storage(out, true, &mut working)?)
    };
    let mut inputs = Vec::with_capacity(size);
    for child in &node.children[1..] {
        inputs.push(if child.id == e::SPACEID {
            leaf(child)?;
            RawOperand::SpaceId(child.require(a::NAME)?.space(&working)?)
        } else {
            RawOperand::Varnode(decode_storage(child, true, &mut working)?)
        });
    }
    let op = PcodeOpRaw::new(opcode, sequence, output, inputs);
    op.validate(&working)?;
    *spaces = working;
    Ok(op)
}
impl PcodeOpRaw {
    pub fn to_xml(&self, spaces: &SpaceTable) -> Result<String> {
        marshal::encode_xml(&encode_raw(self, spaces)?, spaces)
    }
    pub fn to_packed(&self, spaces: &SpaceTable) -> Result<Vec<u8>> {
        marshal::encode_packed(&encode_raw(self, spaces)?, spaces)
    }
    pub fn from_xml(text: &str, sequence: SeqNum, spaces: &mut SpaceTable) -> Result<Self> {
        decode_raw(&marshal::decode_xml(text, spaces)?, sequence, spaces)
    }
    pub fn from_packed(bytes: &[u8], sequence: SeqNum, spaces: &mut SpaceTable) -> Result<Self> {
        decode_raw(&marshal::decode_packed(bytes, spaces)?, sequence, spaces)
    }
}

const VARNODE_ATTRIBUTES: &[(u16, VarnodeFlags)] = &[
    (a::PERSISTS, VarnodeFlags::persist),
    (a::ADDRTIED, VarnodeFlags::addrtied),
    (a::UNAFF, VarnodeFlags::unaffected),
    (a::INPUT, VarnodeFlags::input),
    (a::VOLATILE, VarnodeFlags::volatil),
];

/// 与 Ghidra encodeTree 一致：只输出已经插入 basic block 的操作，
/// 不保存 cover、分析缓存、dead op 和额外标志。内部完整副本可使用 FunctionIr::clone。
pub fn encode_ast(ir: &FunctionIr, spaces: &SpaceTable) -> Result<Element> {
    ir.validate(spaces)?;
    let mut root = Element::new(e::AST);
    let mut varnodes = Element::new(e::VARNODES);
    for vn in ir.varnodes_by_location() {
        if spaces.get(vn.data.space)?.kind == SpaceType::Iop {
            continue;
        }
        let mut node = encode_storage(e::ADDR, vn.data, true, spaces)?
            .with(a::REF, V::Unsigned(vn.id.0 as u64));
        if vn.merge_group != 0 {
            node.attributes
                .push((a::GRP, V::Signed(vn.merge_group as i64)));
        }
        for (id, flag) in VARNODE_ATTRIBUTES {
            if vn.flags.contains(*flag) {
                node.attributes.push((*id, V::Bool(true)));
            }
        }
        varnodes.children.push(node);
    }
    root.children.push(varnodes);
    for block in ir.blocks() {
        let mut node = Element::new(e::BLOCK).with(a::INDEX, V::Signed(block.id.0 as i64));
        let mut ranges = Element::new(e::RANGELIST);
        for range in &block.ranges {
            ranges.children.push(
                Element::new(e::RANGE)
                    .with(a::SPACE, V::Space(range.space))
                    .with(a::FIRST, V::Unsigned(range.first))
                    .with(a::LAST, V::Unsigned(range.last)),
            );
        }
        node.children.push(ranges);
        for id in &block.operations {
            let op = ir.operation(*id)?;
            let mut child = Element::new(e::OP).with(a::CODE, V::Signed(op.opcode.number() as i64));
            child.children.push(encode_sequence(op.sequence, spaces)?);
            child.children.push(match op.output {
                Some(id) => Element::new(e::ADDR).with(a::REF, V::Unsigned(id.0 as u64)),
                None => Element::new(e::VOID),
            });
            for input in &op.inputs {
                child.children.push(match input {
                    Input::Varnode(id) => {
                        if spaces.get(ir.varnode(*id)?.data.space)?.kind == SpaceType::Iop {
                            return Err(error("iop operands must use Input::OpRef"));
                        }
                        Element::new(e::ADDR).with(a::REF, V::Unsigned(id.0 as u64))
                    }
                    Input::SpaceId(id) => Element::new(e::SPACEID).with(a::NAME, V::Space(*id)),
                    Input::OpRef(id) => {
                        let target = ir.operation(*id)?;
                        if target.parent.is_none() {
                            return Err(error("INDIRECT references an uninserted operation"));
                        }
                        Element::new(e::IOP)
                            .with(a::VALUE, V::Unsigned(target.sequence.time as u64))
                    }
                    Input::Unset => Element::new(e::VOID),
                });
            }
            node.children.push(child);
        }
        root.children.push(node);
    }
    for block in ir.blocks() {
        if block.incoming.is_empty() {
            continue;
        }
        let mut node = Element::new(e::BLOCKEDGE).with(a::INDEX, V::Signed(block.id.0 as i64));
        for edge in &block.incoming {
            node.children.push(
                Element::new(e::EDGE)
                    .with(a::END, V::Signed(edge.other.0 as i64))
                    .with(a::REV, V::Signed(edge.reverse_index as i64)),
            );
        }
        root.children.push(node);
    }
    Ok(root)
}

pub fn decode_ast(root: &Element, spaces: &mut SpaceTable) -> Result<FunctionIr> {
    root.expect(e::AST)?;
    let mut working = spaces.clone();
    let spaces_work = &mut working;
    let mut ir = FunctionIr::new();
    let varnodes = root
        .children
        .first()
        .ok_or_else(|| error("AST missing varnodes"))?;
    varnodes.expect(e::VARNODES)?;
    for node in &varnodes.children {
        node.expect(e::ADDR)?;
        let data = decode_storage(node, true, spaces_work)?;
        let id = VarnodeId(u32_value(node.require(a::REF)?)?);
        ir.insert_varnode(id, data, spaces_work)?;
        for (aid, flag) in VARNODE_ATTRIBUTES {
            if node.get(*aid).map(V::boolean).transpose()?.unwrap_or(false) {
                if *aid == a::INPUT {
                    ir.set_input_varnode(id, true)?;
                } else {
                    ir.varnodes.get_mut(&id).unwrap().flags.set(*flag);
                }
            }
        }
        if let Some(group) = node.get(a::GRP) {
            ir.varnodes.get_mut(&id).unwrap().merge_group =
                i16::try_from(group.signed()?).map_err(|_| error("merge group overflow"))?;
        }
    }
    let mut pending = vec![];
    let mut by_time = BTreeMap::new();
    for block in &root.children[1..] {
        if block.id == e::BLOCKEDGE {
            continue;
        }
        block.expect(e::BLOCK)?;
        let bid = BlockId(index(block.require(a::INDEX)?)?);
        ir.insert_block(bid)?;
        let ranges = block
            .children
            .first()
            .ok_or_else(|| error("block missing rangelist"))?;
        ranges.expect(e::RANGELIST)?;
        let mut decoded_ranges = vec![];
        for range in &ranges.children {
            range.expect(e::RANGE)?;
            leaf(range)?;
            decoded_ranges.push(AddressRange::new(
                range.require(a::SPACE)?.space(spaces_work)?,
                range.require(a::FIRST)?.unsigned()?,
                range.require(a::LAST)?.unsigned()?,
            )?);
        }
        ir.set_ranges(bid, decoded_ranges)?;
        for (position, op) in block.children[1..].iter().enumerate() {
            op.expect(e::OP)?;
            if op.children.len() < 2 {
                return Err(error("AST operation missing seqnum/output"));
            }
            let code = OpCode::try_from(u32_value(op.require(a::CODE)?)?)?;
            let seq = decode_sequence(&op.children[0], spaces_work)?;
            let id = ir.new_op(code, seq, op.children.len() - 2)?;
            by_time.insert(seq.time, id);
            let output = &op.children[1];
            leaf(output)?;
            if output.id == e::ADDR {
                ir.set_output(id, Some(VarnodeId(u32_value(output.require(a::REF)?)?)))?;
            } else {
                output.expect(e::VOID)?;
            }
            ir.insert_at(id, bid, position)?;
            pending.push((id, op));
        }
    }
    // 第二遍解析 iop，使引用稍后出现的操作与反向引用都可恢复。
    for (id, op) in pending {
        let mut inputs = vec![];
        for child in &op.children[2..] {
            leaf(child)?;
            inputs.push(match child.id {
                e::VOID => Input::Unset,
                e::ADDR => Input::Varnode(VarnodeId(u32_value(child.require(a::REF)?)?)),
                e::SPACEID => Input::SpaceId(child.require(a::NAME)?.space(spaces_work)?),
                e::IOP => Input::OpRef(
                    *by_time
                        .get(&u32_value(child.require(a::VALUE)?)?)
                        .ok_or_else(|| error("unresolved iop reference"))?,
                ),
                _ => return Err(error("invalid AST operand")),
            });
        }
        ir.set_inputs(id, inputs)?;
    }
    // 文件保存的是入边以及对应的出边槽，不能按文件遍历顺序 add_edge。
    let mut outgoing: BTreeMap<BlockId, BTreeMap<usize, BlockEdge>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for node in root.children.iter().filter(|node| node.id == e::BLOCKEDGE) {
        let to = BlockId(index(node.require(a::INDEX)?)?);
        ir.block(to)?;
        if !seen.insert(to) {
            return Err(error("duplicate blockedge record"));
        }
        for (incoming_slot, child) in node.children.iter().enumerate() {
            child.expect(e::EDGE)?;
            leaf(child)?;
            let from = BlockId(index(child.require(a::END)?)?);
            ir.block(from)?;
            let slot = index(child.require(a::REV)?)? as usize;
            let edge = BlockEdge {
                other: to,
                reverse_index: incoming_slot,
                flags: EdgeFlags(0),
            };
            if outgoing
                .entry(from)
                .or_default()
                .insert(slot, edge)
                .is_some()
            {
                return Err(error("duplicate outgoing edge slot"));
            }
            ir.blocks.get_mut(&to).unwrap().incoming.push(BlockEdge {
                other: from,
                reverse_index: slot,
                flags: EdgeFlags(0),
            });
        }
    }
    for (block, edges) in outgoing {
        if edges.keys().enumerate().any(|(i, k)| i != *k) {
            return Err(error("non-contiguous outgoing edge slots"));
        }
        ir.blocks.get_mut(&block).unwrap().outgoing = edges.into_values().collect();
    }
    ir.validate(spaces_work)?;
    *spaces = working;
    Ok(ir)
}
impl FunctionIr {
    pub fn to_xml(&self, spaces: &SpaceTable) -> Result<String> {
        marshal::encode_xml(&encode_ast(self, spaces)?, spaces)
    }
    pub fn to_packed(&self, spaces: &SpaceTable) -> Result<Vec<u8>> {
        marshal::encode_packed(&encode_ast(self, spaces)?, spaces)
    }
    pub fn from_xml(text: &str, spaces: &mut SpaceTable) -> Result<Self> {
        decode_ast(&marshal::decode_xml(text, spaces)?, spaces)
    }
    pub fn from_packed(bytes: &[u8], spaces: &mut SpaceTable) -> Result<Self> {
        decode_ast(&marshal::decode_packed(bytes, spaces)?, spaces)
    }

    /// 从 SLEIGH 的一段 raw p-code 创建未插入基本块的操作。
    /// raw 存储位置不代表 SSA 身份；每个输入仍是 free varnode，不能冒充已完成 heritage。
    pub fn import_raw(&mut self, raw: &[PcodeOpRaw], spaces: &SpaceTable) -> Result<Vec<OpId>> {
        let mut next = self.clone();
        let mut result = vec![];
        for raw in raw {
            raw.validate(spaces)?;
            let op = next.new_op(raw.opcode, raw.sequence, raw.inputs.len())?;
            if let Some(data) = raw.output {
                let vn = next.new_varnode(data, spaces)?;
                next.set_output(op, Some(vn))?;
            }
            for (slot, operand) in raw.inputs.iter().enumerate() {
                let input = match operand {
                    RawOperand::Varnode(v) => Input::Varnode(next.new_varnode(*v, spaces)?),
                    RawOperand::SpaceId(s) => Input::SpaceId(*s),
                };
                next.set_input(op, slot, input)?;
            }
            result.push(op);
        }
        *self = next;
        Ok(result)
    }
}

/// 机器指令容器。指令长度不是 p-code 数量；局部分支位移只在本容器内解释。
#[derive(Clone, Debug)]
pub struct Instruction {
    pub address: Address,
    pub length: u32,
    pub operations: Vec<PcodeOpRaw>,
}
impl Instruction {
    pub fn validate(&self, spaces: &SpaceTable) -> Result<()> {
        if self.length == 0 {
            return Err(error("instruction length must be positive"));
        }
        spaces.validate_address(self.address)?;
        let mut times = BTreeSet::new();
        for (i, op) in self.operations.iter().enumerate() {
            if op.sequence.address != self.address || !times.insert(op.sequence.time) {
                return Err(error("instruction sequence mismatch"));
            }
            op.validate(spaces)?;
            op.relative_branch_target(i, self.operations.len(), spaces)?;
        }
        Ok(())
    }
}
