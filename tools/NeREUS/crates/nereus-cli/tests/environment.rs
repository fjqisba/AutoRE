use nereus_core::Architecture;
use nereus_remill::Worker;
use serde_json::json;
use std::{fs, path::PathBuf};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn remill_protocol_and_bitcode_roundtrip() {
    let root = project_root();
    let mut worker = Worker::spawn(&root.join("toolchains/bin/nereus-remill-worker.exe")).unwrap();
    let hello = worker.request(json!({"op": "hello"})).unwrap();
    assert_eq!(hello["llvm"], "17.0.6");
    assert_eq!(hello["provider"], "remill");
    // 同一进程处理多条请求，并检查 32/64 位、访存、标志和控制流提升。
    for (index, (architecture, arch_name, hex_bytes)) in [
        (Architecture::Amd64, "amd64", "4801d8"),
        (Architecture::Amd64, "amd64", "b801000000"),
        (Architecture::Amd64, "amd64", "488b4108"),
        (Architecture::Amd64, "amd64", "7505"),
        (Architecture::Amd64, "amd64", "c3"),
        (Architecture::X86, "x86", "01d8"),
    ]
    .iter()
    .enumerate()
    {
        let output = root.join(format!("temp_data/validation/integration-{index}"));
        fs::create_dir_all(&output).unwrap();
        let bytes = hex::decode(hex_bytes).unwrap();
        let decoded = nereus_x86::decode_one(*architecture, 0x401000, &bytes).unwrap();
        let result = worker
            .request(json!({
                "op": "lift-one", "architecture": arch_name, "bytes": hex_bytes,
                "pc": "0x401000", "output_dir": output,
                "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
            }))
            .unwrap();
        assert_eq!(result["length"].as_u64(), Some(decoded.length as u64));
        let summary = nereus_llvm_support::verify_bitcode(&output.join("instruction.bc")).unwrap();
        assert!(summary.verified);
        assert!(summary.functions > 0);
        assert_eq!(result["normalized"], false);
        assert_eq!(result["function_recovered"], false);
    }
    assert!(
        worker
            .request(json!({"op": "unknown-operation"}))
            .unwrap_err()
            .to_string()
            .contains("INVALID_OPERATION")
    );
    let invalid = worker
        .request(json!({
            "op": "lift-one", "architecture": "amd64", "bytes": "0f",
            "pc": "0x401000", "output_dir": root.join("temp_data/validation/invalid"),
            "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
        }))
        .unwrap_err();
    assert!(invalid.to_string().contains("UNSUPPORTED_INSN"));
    // 请求错误不能导致进程假死或污染下一帧。
    assert_eq!(worker.request(json!({"op": "hello"})).unwrap()["ok"], true);
}

#[test]
fn reject_truncated_instruction_and_corrupt_bitcode() {
    assert!(nereus_x86::decode_one(Architecture::Amd64, 0x401000, &[0x0f]).is_err());
    let output = project_root().join("temp_data/validation/corrupt.bc");
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    fs::write(&output, b"not llvm bitcode").unwrap();
    assert!(nereus_llvm_support::verify_bitcode(&output).is_err());
}

#[test]
fn block_lift_preserves_entry_pc_and_terminates_at_control_flow() {
    let root = project_root();
    // mov rcx, 0x1234; jmp rcx：目标常量在同一状态中传递，且 RIP 初始化为入口。
    let bytes = hex::decode("48c7c134120000ffe1").unwrap();
    let block = nereus_x86::decode_basic_block(Architecture::Amd64, 0x401000, &bytes, 10).unwrap();
    assert_eq!(block.instructions.len(), 2);
    assert_eq!(block.terminator, "IndirectBranch");
    assert_eq!(block.byte_length, bytes.len());
    assert!(nereus_x86::decode_basic_block(Architecture::Amd64, 0x401000, &bytes, 1).is_err());
    let output = root.join("temp_data/validation/block-roundtrip");
    fs::create_dir_all(&output).unwrap();
    let mut worker = Worker::spawn(&root.join("toolchains/bin/nereus-remill-worker.exe")).unwrap();
    let result = worker
        .request(json!({
            "op": "lift-block", "architecture": "amd64", "bytes": hex::encode(&bytes),
            "instruction_lengths": [7, 2], "pc": "0x401000", "output_dir": output,
            "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
        }))
        .unwrap();
    assert_eq!(result["instruction_count"], 2);
    assert!(
        nereus_llvm_support::verify_bitcode(&output.join("block.raw.bc"))
            .unwrap()
            .verified
    );
    let il = fs::read_to_string(output.join("block.raw.ll")).unwrap();
    let function = il.split("define ptr @nereus_bb_401000").nth(1).unwrap();
    assert!(function.contains("store i64 4198400"));
    assert!(function.contains("tail call ptr @__remill_jump"));
    let invalid = worker
        .request(json!({
            "op": "lift-block", "architecture": "amd64", "bytes": "eb0090",
            "instruction_lengths": [2, 1], "pc": "0x401000", "output_dir": output,
            "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
        }))
        .unwrap_err();
    assert!(invalid.to_string().contains("INVALID_BLOCK"));
    for (index, (hex_bytes, lengths, helper)) in [
        ("7505", vec![2], "__remill_jump"),
        ("e800000000", vec![5], "__remill_function_call"),
        ("c3", vec![1], "__remill_function_return"),
    ]
    .iter()
    .enumerate()
    {
        let output = root.join(format!("temp_data/validation/block-terminator-{index}"));
        let result = worker
            .request(json!({
                "op": "lift-block", "architecture": "amd64", "bytes": hex_bytes,
                "instruction_lengths": lengths, "pc": "0x401000", "output_dir": output,
                "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
            }))
            .unwrap();
        assert_eq!(result["ok"], true);
        assert!(
            nereus_llvm_support::verify_bitcode(&output.join("block.raw.bc"))
                .unwrap()
                .verified
        );
        let il = fs::read_to_string(output.join("block.raw.ll")).unwrap();
        let function = il.split("define ptr @nereus_bb_401000").nth(1).unwrap();
        assert!(function.contains(&format!("tail call ptr @{helper}")));
        if index == 0 {
            assert!(function.contains("br i1"));
        }
    }
}

#[test]
fn block_discovery_preserves_conditional_successors_and_call_boundary() {
    let branch =
        nereus_x86::decode_basic_block(Architecture::Amd64, 0x401000, &[0x75, 0x05, 0x90], 10)
            .unwrap();
    assert_eq!(branch.byte_length, 2);
    assert_eq!(branch.direct_target, Some(0x401007));
    assert_eq!(branch.fallthrough, Some(0x401002));
    let call = nereus_x86::decode_basic_block(
        Architecture::Amd64,
        0x401000,
        &[0xe8, 0, 0, 0, 0, 0x90],
        10,
    )
    .unwrap();
    assert_eq!(call.byte_length, 5);
    assert_eq!(call.terminator, "Call");
    assert_eq!(call.fallthrough, Some(0x401005));
}

#[test]
fn init_vm_context_lifts_only_the_entry_block() {
    let root = project_root();
    let directory = root.join("temp_data/validation/init-vm-context");
    fs::create_dir_all(&directory).unwrap();
    let mut pe = vec![0_u8; 0x400];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[0xb0..0xb8].copy_from_slice(&0x180000000_u64.to_le_bytes());
    pe[0xd0..0xd4].copy_from_slice(&0x2000_u32.to_le_bytes());
    pe[0x188..0x18d].copy_from_slice(b".text");
    for (offset, value) in [
        (0x190, 0x200_u32),
        (0x194, 0x1000),
        (0x198, 0x200),
        (0x19c, 0x200),
        (0x1ac, 0x60000020),
    ] {
        pe[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    // 首块是 mov eax,1; jmp +0。后继是无效指令，接口必须在 jmp 停止。
    pe[0x200..0x209].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xeb, 0, 0x0f, 0xff]);
    let input = directory.join("entry.dll");
    fs::write(&input, pe).unwrap();
    let session = nereus_vm::VmSession::open(&root, &input, &directory.join("contexts")).unwrap();
    let context = session.init_vm_context(0x180001000).unwrap();
    assert_eq!(context.entry_va, 0x180001000);
    assert_eq!(context.first_block.instructions.len(), 2);
    assert_eq!(context.first_block.byte_length, 7);
    assert_eq!(context.local_ir.matches("\ndefine ").count(), 1);
    assert!(context.local_ir.contains("@nereus_bb_180001000"));
    assert!(context.local_ir.contains("@__remill_jump"));
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(context.output_dir.join("context.json")).unwrap())
            .unwrap();
    assert_eq!(metadata["lifted_block_count"], 1);
    assert_eq!(metadata["successors_followed"], false);
}
