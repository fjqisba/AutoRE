use nereus_remill::Worker;
use nereus_vm::{VmContext, VmSession};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn initialize(name: &str, code: &str) -> VmContext {
    let directory = root()
        .join("temp_data/validation/local-optimization")
        .join(name);
    fs::create_dir_all(&directory).unwrap();
    let mut image = vec![0_u8; 0x400];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (offset, value) in [(0x84, 0x8664_u16), (0x86, 1), (0x94, 0xf0), (0x98, 0x20b)] {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    image[0xb0..0xb8].copy_from_slice(&0x180000000_u64.to_le_bytes());
    for (offset, value) in [
        (0xd0, 0x2000_u32),
        (0x190, 0x200),
        (0x194, 0x1000),
        (0x198, 0x200),
        (0x19c, 0x200),
        (0x1ac, 0x60000020),
    ] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image[0x188..0x18d].copy_from_slice(b".text");
    let bytes = hex::decode(code).unwrap();
    image[0x200..0x200 + bytes.len()].copy_from_slice(&bytes);
    let path = directory.join("fixture.dll");
    fs::write(&path, image).unwrap();
    VmSession::open(&root(), &path, &directory.join("contexts"))
        .unwrap()
        .init_vm_context(0x180001000)
        .unwrap()
}

fn statistics(context: &VmContext) -> Value {
    let metadata: Value =
        serde_json::from_slice(&fs::read(context.output_dir.join("context.json")).unwrap())
            .unwrap();
    metadata["prepared"]["optimization"].clone()
}

fn validate(context: &VmContext, candidate: &Path) -> anyhow::Result<Value> {
    let mut worker = Worker::spawn(&root().join("toolchains/bin/nereus-remill-worker.exe"))?;
    worker.request(json!({
        "op": "validate-local", "reference_bitcode": context.output_dir.join("block.lifted.bc"),
        "optimized_bitcode": candidate, "function_name": "nereus_bb_180001000", "cases": 64
    }))
}

#[test]
fn constant_target_is_folded_and_differential_detects_wrong_rewrite() {
    // mov rcx,1234h; add rcx,1; jmp rcx：需要保留 ADD 的最终 flags。
    let context = initialize("constant-target", "48c7c1341200004883c101ffe1");
    assert!(context.local_ir.contains("i64 4661"));
    let stats = statistics(&context);
    assert!(stats["instructions_after"].as_u64() < stats["instructions_before"].as_u64());
    assert_eq!(
        validate(&context, &context.bitcode_path).unwrap()["ok"],
        true
    );

    // 人为改坏一个输出常量，验证器必须提供反例，而不是只检查 verifier。
    let bad_ll = context.output_dir.join("wrong.ll");
    let bad_bc = context.output_dir.join("wrong.bc");
    fs::write(&bad_ll, context.local_ir.replace("i64 4661", "i64 4662")).unwrap();
    let config: Value =
        serde_json::from_slice(&fs::read(root().join("toolchains/local.json")).unwrap()).unwrap();
    let assembler = PathBuf::from(config["llvm_root"].as_str().unwrap()).join("bin/llvm-as.exe");
    assert!(
        Command::new(assembler)
            .args([bad_ll.as_os_str(), "-o".as_ref(), bad_bc.as_os_str()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        validate(&context, &bad_bc)
            .unwrap_err()
            .to_string()
            .contains("VALIDATION_MISMATCH")
    );
}

#[test]
fn partial_guest_write_is_composed_without_erasing_uncovered_bytes() {
    // store64 [rsp-10h],55667788h; store8 [rsp-0eh],aah; load32 eax,[rsp-10h]; jmp rax。
    let context = initialize(
        "partial-overlap",
        "48c74424f088776655c64424f2aa8b4424f0ffe0",
    );
    assert!(
        context
            .local_ir
            .contains(&format!("i64 {}", 0x55aa7788_u64))
    );
    let stats = statistics(&context);
    assert_eq!(stats["guest_reads_forwarded"], 1);
    assert_eq!(stats["overwritten_guest_writes_removed"], 0);
    assert_eq!(
        validate(&context, &context.bitcode_path).unwrap()["ok"],
        true
    );
}

#[test]
fn uncertain_alias_blocks_guest_load_forwarding() {
    // RBX 可能与 RSP 指向相同内存，不能跨第二条写入转发 RAX。
    let context = initialize("uncertain-alias", "4889042448890b488b1424ffe2");
    assert!(
        context
            .local_ir
            .contains("call i64 @__remill_read_memory_64")
    );
    assert_eq!(statistics(&context)["guest_reads_forwarded"], 0);
}

#[test]
fn popped_flags_still_leave_observable_stack_memory() {
    let context = initialize("flags-roundtrip", "9c9dffe3");
    assert_eq!(statistics(&context)["guest_reads_forwarded"], 1);
    assert!(
        context
            .local_ir
            .contains("call ptr @__remill_write_memory_64")
    );
    assert_eq!(
        validate(&context, &context.bitcode_path).unwrap()["ok"],
        true
    );
}
