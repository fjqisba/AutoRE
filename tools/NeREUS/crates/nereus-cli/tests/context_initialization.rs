use nereus_remill::Worker;
use nereus_vm::VmSession;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str, pieces: &[(usize, Vec<u8>)]) -> (VmSession, PathBuf) {
    let directory = root()
        .join("temp_data/validation/context-initialization")
        .join(name);
    fs::create_dir_all(&directory).unwrap();
    let mut image = vec![0_u8; 0x1200];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (offset, value) in [(0x84, 0x8664_u16), (0x86, 1), (0x94, 0xf0), (0x98, 0x20b)] {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    image[0xb0..0xb8].copy_from_slice(&0x180000000_u64.to_le_bytes());
    for (offset, value) in [
        (0xd0, 0x2000_u32),
        (0x190, 0x1000),
        (0x194, 0x1000),
        (0x198, 0x1000),
        (0x19c, 0x200),
        (0x1ac, 0x60000020),
    ] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image[0x188..0x18d].copy_from_slice(b".text");
    image[0x200..].fill(0xcc);
    for (offset, bytes) in pieces {
        image[0x200 + offset..0x200 + offset + bytes.len()].copy_from_slice(bytes);
    }
    let input = directory.join("fixture.dll");
    fs::write(&input, image).unwrap();
    let output = directory.join("contexts");
    (
        VmSession::open(&root(), &input, &output).unwrap(),
        output.join("180001000"),
    )
}

fn jump(bytes: &mut Vec<u8>, origin: u64, target: u64, call: bool) {
    let next = origin + bytes.len() as u64 + 5;
    bytes.push(if call { 0xe8 } else { 0xe9 });
    bytes.extend_from_slice(
        &i32::try_from(target as i64 - next as i64)
            .unwrap()
            .to_le_bytes(),
    );
}

#[test]
fn internal_calls_extend_runtime_context_despite_register_permutations() {
    for swapped in [false, true] {
        let entry = 0x180001000;
        let mut first = hex::decode("488da42400feffff48896c24284889e548894500").unwrap();
        jump(&mut first, entry, entry + 0x200, false);
        let mut second = hex::decode(concat!(
            "48895d0848894d1048895518",
            "4889753048897d38",
            "4c8945404c894d484c8955504c895d584c8965604c896d684c8975704c897d78",
            "488d850002000048894520",
            "9c8f8580000000"
        ))
        .unwrap();
        jump(&mut second, entry + 0x200, entry + 0x400, false);
        // 同一参数由 R10/R11 交换承载；以实际压栈的数据流识别，不固定寄存器名。
        let mut third = hex::decode(if swapped {
            "4c8d5df849ba001800800100000041534152"
        } else {
            "4c8d55f849bb001800800100000041524153"
        })
        .unwrap();
        jump(&mut third, entry + 0x400, entry + 0x900, true);
        let mut runtime =
            hex::decode("415641555741545541574883ec684889e54c8b9da00000004c8b95a8000000").unwrap();
        jump(&mut runtime, entry + 0x900, entry + 0xb00, true);
        // 丢弃内部 CALL 的返回地址，继续写运行时上下文，最后故意保留未知目标。
        let continuation = hex::decode("488d6424084c895d60ffe0").unwrap();
        let (session, directory) = fixture(
            if swapped {
                "runtime-swapped"
            } else {
                "runtime"
            },
            &[
                (0, first),
                (0x200, second),
                (0x400, third),
                (0x900, runtime),
                (0xb00, continuation),
            ],
        );
        let error = session
            .init_vm_context(entry)
            .err()
            .expect("未知目标必须报错");
        assert!(
            error.to_string().contains("BRANCH_TARGET_UNRESOLVED"),
            "{error:#}"
        );
        let state: Value =
            serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap())
                .unwrap();
        assert_eq!(state["blocks"].as_array().unwrap().len(), 5);
        assert_eq!(state["initialization_complete"], false);
        assert_eq!(state["stage"], "BuildingRuntimeContext");
        assert_eq!(
            state["transitions"][2]["semantics"],
            "push-return-address-and-internal-jump"
        );
        assert_eq!(
            state["transitions"][3]["semantics"],
            "push-return-address-and-internal-jump"
        );
        let writes = state["initialization"]["runtime_context_writes"]
            .as_array()
            .unwrap();
        assert!(
            writes
                .iter()
                .any(|write| write["offset"] == 0x60 && write["constant"] == "0x180001800")
        );
        let roles = state["initialization"]["register_roles"]
            .as_array()
            .unwrap();
        assert!(
            roles
                .iter()
                .any(|role| role["register"] == "R10" && role["role"] == "guest_context_pointer")
        );
        let mut worker =
            Worker::spawn(&root().join("toolchains/bin/nereus-remill-worker.exe")).unwrap();
        let validation = worker
            .request(json!({"op":"validate-local",
            "reference_bitcode":directory.join("block.lifted.bc"),
            "optimized_bitcode":directory.join("block.optimized.bc"),
            "function_name":"nereus_bb_180001000","cases":64}))
            .unwrap();
        assert_eq!(validation["ok"], true);
    }
}

#[test]
fn symbolic_or_multiple_targets_raise_errors() {
    {
        let (name, bytes) = ("symbolic", "ffe0");
        let (session, directory) = fixture(name, &[(0, hex::decode(bytes).unwrap())]);
        let error = session
            .init_vm_context(0x180001000)
            .err()
            .expect("应拒绝未知目标");
        assert!(
            error.to_string().contains("BRANCH_TARGET_UNRESOLVED"),
            "{name}: {error:#}"
        );
        let report: Value =
            serde_json::from_slice(&fs::read(directory.join("initialization.error.json")).unwrap())
                .unwrap();
        assert_eq!(report["code"], "BRANCH_TARGET_UNRESOLVED");
        assert_eq!(
            report["history"][0]["initialization"]["exits"][0]["kind"],
            "__remill_jump"
        );
        assert_eq!(report["history"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn constants_outside_image_and_initialization_cycles_are_rejected() {
    let (session, _) = fixture(
        "unmapped",
        &[(0, hex::decode("48c7c100000070ffe1").unwrap())],
    );
    assert!(
        session
            .init_vm_context(0x180001000)
            .err()
            .unwrap()
            .to_string()
            .contains("BRANCH_TARGET_UNREACHABLE")
    );
    let (session, _) = fixture("cycle", &[(0, vec![0xeb, 0xfe])]);
    assert!(
        session
            .init_vm_context(0x180001000)
            .err()
            .unwrap()
            .to_string()
            .contains("INITIALIZATION_CYCLE")
    );
}

#[test]
fn register_value_from_prior_block_resolves_next_branch() {
    let entry = 0x180001000;
    let mut first = hex::decode("48b8001400800100000050").unwrap();
    jump(&mut first, entry, entry + 0x200, false);
    let second = hex::decode("58ffe0").unwrap();
    let (session, directory) = fixture(
        "cross-block-stack",
        &[(0, first), (0x200, second), (0x400, vec![0xff, 0xe3])],
    );
    let error = session.init_vm_context(entry).err().unwrap();
    assert!(error.to_string().contains("BRANCH_TARGET_UNRESOLVED"));
    let report: Value =
        serde_json::from_slice(&fs::read(directory.join("initialization.error.json")).unwrap())
            .unwrap();
    let history = report["history"].as_array().unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[1]["initialization"]["next_target"], "0x180001400");
    assert_eq!(history[2]["block_entry"], "0x180001400");
}

#[test]
fn call_alone_does_not_imply_context_completion() {
    let entry = 0x180001000;
    let mut first = Vec::new();
    jump(&mut first, entry, entry + 0x200, true);
    let (session, directory) = fixture("early-call", &[(0, first), (0x200, vec![0xff, 0xe0])]);
    assert!(
        session
            .init_vm_context(entry)
            .err()
            .unwrap()
            .to_string()
            .contains("BRANCH_TARGET_UNRESOLVED")
    );
    let report: Value =
        serde_json::from_slice(&fs::read(directory.join("initialization.error.json")).unwrap())
            .unwrap();
    assert_eq!(report["history"].as_array().unwrap().len(), 2);
    assert_eq!(report["history"][0]["initialization"]["complete"], false);
}

#[test]
fn internal_call_return_address_is_part_of_machine_state() {
    let entry = 0x180001000;
    let mut call = Vec::new();
    jump(&mut call, entry, entry + 0x200, true);
    // 真实 RET 从同一 guest 栈弹出 CALL 返回地址，不能将其视为分析函数退出。
    call.extend_from_slice(&[0xff, 0xe0]);
    let (session, directory) = fixture("call-ret-state", &[(0, call), (0x200, vec![0xc3])]);
    assert!(
        session
            .init_vm_context(entry)
            .err()
            .unwrap()
            .to_string()
            .contains("BRANCH_TARGET_UNRESOLVED")
    );
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(state["blocks"].as_array().unwrap().len(), 3);
    assert_eq!(state["blocks"][1]["start_pc"], entry + 0x200);
    assert_eq!(state["blocks"][2]["start_pc"], entry + 5);
    assert_eq!(
        state["transitions"][0]["semantics"],
        "push-return-address-and-internal-jump"
    );
    assert_eq!(state["transitions"][1]["native_kind"], "Return");
}

#[test]
fn virtual_conditional_jump_preserves_both_semantic_edges() {
    let code = hex::decode("85c048b9001100800100000048ba8011008001000000480f45caffe1").unwrap();
    let (session, directory) = fixture("virtual-conditional", &[(0, code)]);
    let error = session.init_vm_context(0x180001000).err().unwrap();
    assert!(error.to_string().contains("VJCC_FRONTIER"), "{error:#}");
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(state["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(state["prepared"]["branch"]["kind"], "conditional");
    assert_eq!(state["prepared"]["branch"]["target_set_complete"], true);
    let graph = &state["semantic_graph"];
    assert_eq!(graph["edges"].as_array().unwrap().len(), 2);
    for edge in graph["edges"].as_array().unwrap() {
        assert_eq!(edge["kind"], "conditional");
        assert!(edge["condition"]["condition_smt2"].is_string());
    }
    assert_eq!(graph["nodes"].as_object().unwrap().len(), 3);
    let queries = state["prepared"]["branch"]["queries"].as_array().unwrap();
    assert_eq!(queries.last().unwrap()["status"], "unsat");
    let dot = fs::read_to_string(directory.join("semantic-graph.dot")).unwrap();
    let svg = fs::read_to_string(directory.join("semantic-graph.svg")).unwrap();
    for instruction in state["blocks"][0]["instructions"].as_array().unwrap() {
        let rip = format!("0x{:X}", instruction["pc"].as_u64().unwrap());
        assert!(dot.contains(&rip));
        assert!(svg.contains(&rip));
    }
    assert!(svg.contains("<svg"));
    assert!(!svg.contains("<image"));
    assert!(dot.contains("尚未分析 / discovered frontier"));
    assert!(!directory.join("semantic-graph.png").exists());
}

#[test]
fn native_conditional_jump_is_not_flattened() {
    let (session, directory) = fixture(
        "native-conditional",
        &[(0, vec![0x75, 2, 0x90, 0x90, 0xff, 0xe0])],
    );
    let error = session.init_vm_context(0x180001000).err().unwrap();
    assert!(error.to_string().contains("VJCC_FRONTIER"), "{error:#}");
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(
        state["prepared"]["branch"]["targets"],
        json!(["0x180001002", "0x180001004"])
    );
}

#[test]
fn unlimited_indirect_target_is_not_misclassified_as_jcc() {
    let (session, directory) = fixture("multi-target", &[(0, vec![0xff, 0xe0])]);
    assert!(session.init_vm_context(0x180001000).is_err());
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(state["prepared"]["branch"]["kind"], "computed-indirect");
    assert_eq!(state["prepared"]["branch"]["target_set_complete"], false);
    assert_eq!(
        state["prepared"]["branch"]["queries"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn snapshot_pointer_chain_converges_beyond_the_old_sixteen_round_limit() {
    // 每次只能从当前 IR 暴露下一层地址，模拟跨块解码依赖；不能按固定轮数提交粗糙目标。
    let entry = 0x180001000_u64;
    let depth = 24;
    let mut code = vec![0x48, 0xb9]; // mov rcx, first_slot
    code.extend_from_slice(&(entry + 0x800).to_le_bytes());
    for _ in 0..depth {
        code.extend_from_slice(&[0x48, 0x8b, 0x09]); // mov rcx, [rcx]
    }
    code.extend_from_slice(&[0xff, 0xe1]); // jmp rcx
    let mut slots = Vec::new();
    for index in 0..depth {
        let target = if index + 1 == depth {
            entry + 0x200
        } else {
            entry + 0x800 + (index + 1) * 8
        };
        slots.extend_from_slice(&target.to_le_bytes());
    }
    let (session, directory) = fixture(
        "deep-snapshot-chain",
        &[(0, code), (0x200, vec![0xff, 0xe0]), (0x800, slots)],
    );
    let error = session.init_vm_context(entry).err().unwrap();
    assert!(
        error.to_string().contains("BRANCH_TARGET_UNRESOLVED"),
        "{error:#}"
    );
    let progress: Value = serde_json::from_slice(
        &fs::read(directory.join("rounds/00/optimization.progress.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(progress["converged"], true);
    assert!(progress["iterations"].as_u64().unwrap() > 16);
    assert_eq!(
        progress["worker"]["initialization"]["next_target"],
        "0x180001200"
    );
    let last = progress["history"].as_array().unwrap().last().unwrap();
    assert_eq!(last["ir_changed"], false);
    assert_eq!(last["state_changed"], false);
    assert_eq!(last["facts_changed"], false);
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(state["blocks"].as_array().unwrap().len(), 2);
}

#[test]
fn arithmetic_mask_virtual_jcc_is_detected() {
    // 用 setz/neg/and/add 编码两目标，不要求目标 IR 必须长成 select。
    let code =
        hex::decode("85c00f94c10fb6c948f7d981e18000000048b800110080010000004801c8ffe0").unwrap();
    let (session, directory) = fixture("arithmetic-jcc", &[(0, code)]);
    let error = session.init_vm_context(0x180001000).err().unwrap();
    assert!(error.to_string().contains("VJCC_FRONTIER"), "{error:#}");
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_eq!(
        state["prepared"]["branch"]["targets"],
        json!(["0x180001100", "0x180001180"])
    );
    assert_eq!(
        state["semantic_graph"]["edges"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn image_fact_written_on_path_is_not_reused_as_original_constant() {
    // 先通过已知地址改写映像槽，再读取它；写入是输入 RAX，不能仍用文件里的目标。
    let code = hex::decode("48b90018008001000000488901488b11ffe2").unwrap();
    let target = 0x180001900_u64.to_le_bytes().to_vec();
    let (session, directory) = fixture("image-write-invalidates", &[(0, code), (0x800, target)]);
    assert!(session.init_vm_context(0x180001000).is_err());
    let state: Value =
        serde_json::from_slice(&fs::read(directory.join("state-machine.json")).unwrap()).unwrap();
    assert_ne!(state["prepared"]["branch"]["kind"], "direct");
    assert_eq!(
        state["prepared"]["optimization"]["snapshot_reads_promoted"],
        0
    );
}

#[test]
fn vip_is_measured_before_each_instruction_and_advances_after_cursor_store() {
    use nereus_core::Architecture;
    for carrier in ["R10", "R11"] {
        let bytes = hex::decode(if carrier == "R11" {
            "49bb0018008001000000488dac2400ffffff4c895d604983c3084c895d60ffe0"
        } else {
            "49ba0018008001000000488dac2400ffffff4c8955604983c2084c895560ffe0"
        })
        .unwrap();
        let block =
            nereus_x86::decode_basic_block(Architecture::Amd64, 0x180001000, &bytes, 32).unwrap();
        let directory = root()
            .join("temp_data/validation/instruction-vip")
            .join(carrier);
        fs::create_dir_all(&directory).unwrap();
        let mut worker =
            Worker::spawn(&root().join("toolchains/bin/nereus-remill-worker.exe")).unwrap();
        let lifted=worker.request(json!({"op":"lift-block","architecture":"amd64","pc":"0x180001000",
            "bytes":hex::encode(&bytes),"instruction_lengths":block.instructions.iter().map(|item|item.instruction.length).collect::<Vec<_>>(),
            "trace_instruction_vip":true,"trace_seed_register":carrier,"output_dir":directory,
            "semantics_dir":root().join("toolchains/remill-install/share/remill/17/semantics")})).unwrap();
        nereus_vm::prepare_block_il(
            &root(),
            &directory,
            lifted["function_name"].as_str().unwrap(),
        )
        .unwrap();
        let optimized = worker
            .request(
                json!({"op":"optimize-local","input_bitcode":directory.join("block.lifted.bc"),
            "output_dir":directory,"function_name":lifted["function_name"],
            "vip_trace":{"stream_base":"0x180001800","cursor_slot_from_entry_rsp":-0xa0}}),
            )
            .unwrap();
        let rows = optimized["instruction_vips"].as_array().unwrap();
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0]["vip"], "0x0");
        assert_eq!(rows[0]["vip_initialized"], false);
        assert_eq!(rows[1]["vip"], "0x180001800");
        assert_eq!(rows[3]["vip"], "0x180001800");
        // 运算寄存器先增加 8，游标在下一条 store 完成前仍为旧值。
        assert_eq!(rows[4]["vip"], "0x180001800");
        assert_eq!(rows[5]["vip"], "0x180001808");
        for row in rows {
            assert_eq!(row["boundary"], "before-native-instruction");
        }
    }
}
