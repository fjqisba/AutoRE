// SPDX-License-Identifier: Apache-2.0
use ghidra_pcode_ir::{
    address::*,
    flags::*,
    marshal::{self, attribute as a, element as e, Element, Value as V},
    wire, BlockId, FunctionIr, Input, OpCode, PcodeOpRaw, RawOperand, SeqNum, VarnodeData,
};

fn spaces() -> SpaceTable {
    let mut spaces = SpaceTable::new();
    for (id, name, kind) in [
        (0, "const", SpaceType::Constant),
        (1, "ram", SpaceType::Processor),
        (2, "register", SpaceType::Processor),
        (3, "unique", SpaceType::Internal),
        (4, "join", SpaceType::Join),
    ] {
        spaces
            .insert(AddrSpace::new(id, name, kind, 8, 1, Endian::Little).unwrap())
            .unwrap();
    }
    spaces
}
fn seq(time: u32) -> SeqNum {
    SeqNum::new(Address::new(SpaceId(1), 0x1000), time)
}
fn reg(offset: u64) -> VarnodeData {
    VarnodeData::new(SpaceId(2), offset, 8)
}
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .expect("generate native oracle fixtures first; see README")
}

#[test]
fn opcode_numbers_match_upstream_header() {
    let header = include_str!("../../../native/decompiler/cpp/opcodes.hh");
    for line in header.lines().filter(|l| l.trim().starts_with("CPUI_")) {
        let declaration = line
            .trim()
            .split(',')
            .next()
            .unwrap()
            .split("//")
            .next()
            .unwrap();
        let (name, number) = declaration.split_once('=').unwrap();
        let number: u32 = number.trim().parse().unwrap();
        if name.trim() == "CPUI_MAX" {
            assert_eq!(number, OpCode::MAX);
        } else {
            let op: OpCode = name.trim().strip_prefix("CPUI_").unwrap().parse().unwrap();
            assert_eq!(op.number(), number);
        }
    }
    assert!(OpCode::try_from(45).is_err());
    assert!(OpCode::try_from(75).is_err());
    assert_eq!(OpCode::ALL.len(), 74);
}

#[test]
fn opcode_flags_match_upstream_typeop_constructors() {
    let source = include_str!("../../../native/decompiler/cpp/typeop.cc");
    let flags = [
        ("unary", OpFlags::unary),
        ("binary", OpFlags::binary),
        ("ternary", OpFlags::ternary),
        ("special", OpFlags::special),
        ("branch", OpFlags::branch),
        ("call", OpFlags::call),
        ("returns", OpFlags::returns),
        ("nocollapse", OpFlags::nocollapse),
        ("marker", OpFlags::marker),
        ("booloutput", OpFlags::booloutput),
        ("commutative", OpFlags::commutative),
        ("coderef", OpFlags::coderef),
        ("has_callspec", OpFlags::has_callspec),
        ("return_copy", OpFlags::return_copy),
    ];
    let mut checked = 0;
    for constructor in source.split("\nTypeOp").skip(1) {
        let Some(body) = constructor.split('}').next() else {
            continue;
        };
        let Some((_, rest)) = body.split_once("CPUI_") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        let Ok(op) = name.parse::<OpCode>() else {
            continue;
        };
        let Some((_, rest)) = body.split_once("opflags =") else {
            continue;
        };
        let expr = rest.split(';').next().unwrap();
        let mut value = 0;
        for token in expr.split("PcodeOp::").skip(1) {
            let name: String = token
                .chars()
                .take_while(|c| c.is_ascii_alphabetic() || *c == '_')
                .collect();
            value |= flags
                .iter()
                .find(|(n, _)| *n == name)
                .expect("unknown native opcode flag")
                .1
                 .0;
        }
        assert_eq!(op.default_flags().0, value, "{op}");
        checked += 1;
    }
    assert_eq!(checked, 73);
}

#[test]
fn native_load_wire_is_byte_identical() {
    let mut spaces = spaces();
    let raw = PcodeOpRaw::new(
        OpCode::LOAD,
        seq(0),
        Some(reg(0x4000)),
        vec![
            RawOperand::SpaceId(SpaceId(1)),
            RawOperand::Varnode(reg(0x4008)),
        ],
    );
    let packed = fixture("native_load.packed");
    assert_eq!(raw.to_packed(&spaces).unwrap(), packed);
    assert_eq!(
        raw.to_xml(&spaces).unwrap().as_bytes(),
        fixture("native_load.xml")
    );
    let parsed = PcodeOpRaw::from_packed(&packed, seq(0), &mut spaces).unwrap();
    assert_eq!(parsed.opcode, OpCode::LOAD);
    assert_eq!(parsed.inputs, raw.inputs);
    assert_eq!(parsed.output, raw.output);
    assert_eq!(
        PcodeOpRaw::from_xml(&raw.to_xml(&spaces).unwrap(), seq(0), &mut spaces)
            .unwrap()
            .to_packed(&spaces)
            .unwrap(),
        packed
    );
}

#[test]
fn native_signed_unsigned_strings_and_extended_ids() {
    let spaces = spaces();
    let node = Element::new(e::OP)
        .with(a::SIZE, V::Signed(i64::MIN))
        .with(a::OFFSET, V::Unsigned(u64::MAX))
        .with(a::VOLATILE, V::Bool(true))
        .with(a::NAME, V::Text("a<&\"b".into()));
    let bytes = fixture("native_scalars.packed");
    assert_eq!(marshal::encode_packed(&node, &spaces).unwrap(), bytes);
    assert_eq!(marshal::decode_packed(&bytes, &spaces).unwrap(), node);
    let xml = marshal::encode_xml(&node, &spaces).unwrap();
    assert_eq!(marshal::decode_xml(&xml, &spaces).unwrap(), node);
}

#[test]
fn native_sequence_bytes_and_cpp_equality_contract() {
    let mut spaces = spaces();
    let sequence = SeqNum::new(Address::new(SpaceId(1), 0xfffffffffffffff0), 0x89abcdef);
    let node = wire::encode_sequence(sequence, &spaces).unwrap();
    let bytes = fixture("native_seqnum.packed");
    assert_eq!(marshal::encode_packed(&node, &spaces).unwrap(), bytes);
    let restored = wire::decode_sequence(
        &marshal::decode_packed(&bytes, &spaces).unwrap(),
        &mut spaces,
    )
    .unwrap();
    assert_eq!(sequence.key(), restored.key());
    let other = SeqNum::new(Address::new(SpaceId(1), 0), sequence.time);
    assert!(sequence.same_time(other));
    assert_ne!(sequence.compare(other), std::cmp::Ordering::Equal);
}

#[test]
fn address_wrapping_and_word_addressing() {
    let space = AddrSpace::new(1, "ram", SpaceType::Processor, 2, 2, Endian::Little).unwrap();
    assert_eq!(space.highest(), 0x1ffff);
    assert_eq!(space.wrap_offset(u64::MAX), 0x1ffff);
    assert_eq!(space.wrap_offset(0x20004), 4);
    assert_eq!(space.word_to_byte(0x10), 0x20);
    assert_eq!(space.byte_to_word(0x20), 0x10);
}

#[test]
fn varnode_order_and_contiguity_follow_endianness() {
    assert!(VarnodeData::new(SpaceId(2), 0, 8) < VarnodeData::new(SpaceId(2), 0, 4));
    let spaces = spaces();
    assert!(reg(8).is_contiguous(reg(0), &spaces).unwrap());
    assert!(!reg(0).is_contiguous(reg(8), &spaces).unwrap());
    let mut big = SpaceTable::new();
    big.insert(AddrSpace::new(2, "register", SpaceType::Processor, 8, 1, Endian::Big).unwrap())
        .unwrap();
    assert!(reg(0).is_contiguous(reg(8), &big).unwrap());
}

#[test]
fn def_use_repeated_operands_and_mutations() {
    let spaces = spaces();
    let mut ir = FunctionIr::new();
    let x = ir.new_varnode(reg(0), &spaces).unwrap();
    let y = ir.new_varnode(reg(0), &spaces).unwrap();
    assert_ne!(x, y);
    ir.set_input_varnode(x, true).unwrap();
    let op = ir.new_op(OpCode::INT_ADD, seq(0), 2).unwrap();
    ir.set_inputs(op, vec![Input::Varnode(x), Input::Varnode(x)])
        .unwrap();
    ir.set_output(op, Some(y)).unwrap();
    assert_eq!(ir.varnode(x).unwrap().uses().count(), 2);
    ir.remove_input(op, 0).unwrap();
    assert_eq!(ir.varnode(x).unwrap().uses().next().unwrap().slot, 0);
    ir.replace_all_uses(x, y).unwrap();
    assert_eq!(ir.varnode(x).unwrap().uses().count(), 0);
    assert!(ir.destroy_varnode(y).is_err());
    ir.validate(&spaces).unwrap();
    ir.destroy_op(op).unwrap();
    ir.destroy_varnode(y).unwrap();
    ir.validate(&spaces).unwrap();
}

#[test]
fn input_constant_and_opcode_flags_are_managed() {
    let spaces = spaces();
    let mut ir = FunctionIr::new();
    let constant = ir.new_constant(1, 0x1ff, &spaces).unwrap();
    assert_eq!(ir.varnode(constant).unwrap().data().offset, 0xff);
    assert_eq!(ir.varnode(constant).unwrap().nonzero_mask(), 0xff);
    assert_eq!(ir.varnode(constant).unwrap().consumed(), u64::MAX);
    assert!(ir.set_input_varnode(constant, true).is_err());
    let op = ir.new_op(OpCode::CALL, seq(0), 0).unwrap();
    assert!(ir.operation(op).unwrap().flags().contains(OpFlags::call));
    ir.set_opcode(op, OpCode::INT_EQUAL).unwrap();
    assert!(!ir.operation(op).unwrap().flags().contains(OpFlags::call));
    assert!(ir
        .operation(op)
        .unwrap()
        .flags()
        .contains(OpFlags::booloutput | OpFlags::commutative));
}

#[test]
fn cfg_self_parallel_edges_and_phi_deletion() {
    let spaces = spaces();
    let mut ir = FunctionIr::new();
    let b = BlockId(0);
    ir.insert_block(b).unwrap();
    ir.add_edge(b, b, EdgeFlags(0)).unwrap();
    ir.add_edge(b, b, EdgeFlags(0)).unwrap();
    let x = ir.new_constant(8, 1, &spaces).unwrap();
    let phi = ir.new_op(OpCode::MULTIEQUAL, seq(0), 2).unwrap();
    ir.set_inputs(phi, vec![Input::Varnode(x); 2]).unwrap();
    ir.insert_at(phi, b, 0).unwrap();
    ir.validate(&spaces).unwrap();
    ir.remove_edge(b, 0).unwrap();
    ir.validate(&spaces).unwrap();
    assert_eq!(ir.operation(phi).unwrap().inputs().len(), 1);
    ir.add_edge_with_phi(b, b, EdgeFlags::f_back_edge, &[(phi, Input::Varnode(x))])
        .unwrap();
    ir.swap_out_edges(b).unwrap();
    ir.validate(&spaces).unwrap();
    ir.remove_edge(b, 1).unwrap();
    ir.remove_edge(b, 0).unwrap();
    ir.validate(&spaces).unwrap();
}

#[test]
fn ast_roundtrip_preserves_incoming_order_and_forward_iop() {
    let mut spaces = spaces();
    let mut ir = FunctionIr::new();
    for b in 0..3 {
        ir.insert_block(BlockId(b)).unwrap();
    }
    // 出边顺序与文件中 blockedge 顺序不同，暴露错误的顺序恢复实现。
    ir.add_edge(BlockId(0), BlockId(2), EdgeFlags(0)).unwrap();
    ir.add_edge(BlockId(0), BlockId(1), EdgeFlags(0)).unwrap();
    ir.add_edge(BlockId(1), BlockId(2), EdgeFlags(0)).unwrap();
    let x = ir.new_constant(8, 0x42, &spaces).unwrap();
    let indirect = ir.new_op(OpCode::INDIRECT, seq(0), 2).unwrap();
    let call = ir.new_op(OpCode::CALL, seq(1), 0).unwrap();
    ir.set_inputs(indirect, vec![Input::Varnode(x), Input::OpRef(call)])
        .unwrap();
    ir.insert_at(indirect, BlockId(0), 0).unwrap();
    ir.insert_at(call, BlockId(0), 1).unwrap();
    let phi = ir.new_op(OpCode::MULTIEQUAL, seq(2), 2).unwrap();
    ir.set_inputs(phi, vec![Input::Varnode(x); 2]).unwrap();
    ir.insert_at(phi, BlockId(2), 0).unwrap();
    let xml = ir.to_xml(&spaces).unwrap();
    let packed = ir.to_packed(&spaces).unwrap();
    let restored = FunctionIr::from_xml(&xml, &mut spaces).unwrap();
    assert_eq!(restored.to_packed(&spaces).unwrap(), packed);
    let restored = FunctionIr::from_packed(&packed, &mut spaces).unwrap();
    assert_eq!(
        restored.block(BlockId(0)).unwrap().true_out(),
        Some(BlockId(1))
    );
    assert_eq!(restored.to_xml(&spaces).unwrap(), xml);
}

#[test]
fn join_and_register_named_storage_roundtrip() {
    let mut spaces = spaces();
    spaces.add_register("x0", reg(0x4000)).unwrap();
    let join = spaces
        .find_add_join(vec![reg(0x4008), reg(0x4000)], 0)
        .unwrap();
    assert_eq!(join.offset, 0);
    assert_eq!(join.size, 16);
    assert_eq!(
        spaces
            .find_add_join(vec![reg(0x4008), reg(0x4000)], 0)
            .unwrap(),
        join
    );
    let float = spaces.find_add_join(vec![reg(0x4000)], 4).unwrap();
    assert_eq!(float.offset, 16);
    let raw = PcodeOpRaw::new(
        OpCode::COPY,
        seq(0),
        Some(join),
        vec![RawOperand::Varnode(join)],
    );
    let xml = raw.to_xml(&spaces).unwrap();
    assert!(xml.contains("piece1="));
    let restored = PcodeOpRaw::from_xml(&xml, seq(0), &mut spaces).unwrap();
    assert_eq!(restored.output, Some(join));
    let named = "<op code='1' size='1'><register name='x0'/><addr space='const' offset='0x1' size='8'/></op>";
    assert_eq!(
        PcodeOpRaw::from_xml(named, seq(0), &mut spaces)
            .unwrap()
            .output,
        Some(reg(0x4000))
    );
}

#[test]
fn invalid_decode_does_not_mutate_space_table() {
    let mut spaces = spaces();
    let before = spaces.clone();
    let text = "<op code='2' size='1'><addr space='join' piece1='register:0x0:8' piece2='register:0x8:8'/><addr space='const' offset='0' size='8'/></op>";
    assert!(PcodeOpRaw::from_xml(text, seq(0), &mut spaces).is_err());
    assert_eq!(spaces, before);
}

#[test]
fn malformed_xml_and_packed_are_rejected() {
    let spaces = spaces();
    for xml in [
        "<op>",
        "<op></addr>",
        "<op code='1' code='2'/>",
        "<!DOCTYPE op><op/>",
        "<op name='&external;'/>",
        "<op/><op/>",
        "<op name='x'code='1'/>",
    ] {
        assert!(marshal::decode_xml(xml, &spaces).is_err(), "{xml}");
    }
    let packed = fixture("native_load.packed");
    for size in 0..packed.len() {
        assert!(marshal::decode_packed(&packed[..size], &spaces).is_err());
    }
    let mut trailing = packed.clone();
    trailing.push(0);
    assert!(marshal::decode_packed(&trailing, &spaces).is_err());
    let mut deep = "<op>".repeat(130);
    deep.push_str(&"</op>".repeat(130));
    assert!(marshal::decode_xml(&deep, &spaces).is_err());
}

#[test]
fn raw_import_rolls_back_on_duplicate_time() {
    let spaces = spaces();
    let mut ir = FunctionIr::new();
    let op = PcodeOpRaw::new(
        OpCode::COPY,
        seq(0),
        Some(reg(0)),
        vec![RawOperand::Varnode(reg(8))],
    );
    assert!(ir.import_raw(&[op.clone(), op.clone()], &spaces).is_err());
    assert_eq!(ir.operations().count(), 0);
    assert_eq!(ir.varnodes().count(), 0);
    ir.import_raw(&[op], &spaces).unwrap();
    ir.validate(&spaces).unwrap();
}

#[test]
fn local_pcode_branch_is_relative_to_current_operation() {
    let spaces = spaces();
    let mut op = PcodeOpRaw::new(
        OpCode::BRANCH,
        seq(0),
        None,
        vec![RawOperand::Varnode(VarnodeData::new(
            SpaceId(0),
            u64::MAX,
            8,
        ))],
    );
    assert_eq!(op.relative_branch_target(2, 4, &spaces).unwrap(), Some(1));
    assert!(op.relative_branch_target(0, 4, &spaces).is_err());
    op.inputs[0] = RawOperand::Varnode(VarnodeData::new(SpaceId(0), 2, 8));
    assert_eq!(op.relative_branch_target(2, 4, &spaces).unwrap(), Some(4));
}
