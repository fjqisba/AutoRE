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
