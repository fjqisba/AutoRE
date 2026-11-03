// SPDX-License-Identifier: Apache-2.0
//! 构造 ADD X0, X0, #1 对应的 IR；这里演示 IR API，不伪装成机器码解码器。
use ghidra_pcode_ir::{
    flags::EdgeFlags, AddrSpace, Address, BlockId, Endian, FunctionIr, Input, OpCode, SeqNum,
    SpaceTable, SpaceType, VarnodeData,
};

fn main() -> ghidra_pcode_ir::Result<()> {
    let mut spaces = SpaceTable::new();
    for (id, name, kind) in [
        (0, "const", SpaceType::Constant),
        (1, "ram", SpaceType::Processor),
        (2, "register", SpaceType::Processor),
        (3, "unique", SpaceType::Internal),
    ] {
        spaces.insert(AddrSpace::new(id, name, kind, 8, 1, Endian::Little)?)?;
    }
    let ram = spaces.named("ram")?.id;
    let registers = spaces.named("register")?.id;
    let mut ir = FunctionIr::new();
    ir.insert_block(BlockId(0))?;
    ir.insert_block(BlockId(1))?;
    let before = ir.new_varnode(VarnodeData::new(registers, 0x4000, 8), &spaces)?;
    ir.set_input_varnode(before, true)?;
    let one = ir.new_constant(8, 1, &spaces)?;
    // 相同存储地址的两个 Varnode 是不同 SSA 值。
    let after = ir.new_varnode(VarnodeData::new(registers, 0x4000, 8), &spaces)?;
    let op = ir.new_op(
        OpCode::INT_ADD,
        SeqNum::new(Address::new(ram, 0x1000), 0),
        2,
    )?;
    ir.set_inputs(op, vec![Input::Varnode(before), Input::Varnode(one)])?;
    ir.set_output(op, Some(after))?;
    ir.insert_at(op, BlockId(0), 0)?;
    ir.add_edge(BlockId(0), BlockId(1), EdgeFlags(0))?;
    ir.validate(&spaces)?;
    let xml = ir.to_xml(&spaces)?;
    let packed = ir.to_packed(&spaces)?;
    let restored = FunctionIr::from_packed(&packed, &mut spaces)?;
    println!("{xml}");
    println!(
        "Packed: {} bytes; restored: {} varnodes, {} ops, {} blocks",
        packed.len(),
        restored.varnodes().count(),
        restored.operations().count(),
        restored.blocks().count()
    );
    Ok(())
}
