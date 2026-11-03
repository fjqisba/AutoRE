use anyhow::{Context, Result, bail};
use nereus_core::{Architecture, DecodedBlock};
use nereus_loader::{MappedAddress, PeImage};
use nereus_remill::Worker;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
mod branch;
mod graph_export;
mod semantic_graph;
pub use semantic_graph::SemanticAddress;
use semantic_graph::{SemanticGraph, VipTracker};

/// 会话绑定模块和提升环境；入口地址是 init_vm_context 唯一的调用参数。
pub struct VmSession {
    root: PathBuf,
    module_path: PathBuf,
    module_bytes: Vec<u8>,
    image: PeImage,
    output_root: PathBuf,
}

/// 保存完成初始化后的合并 IR；first_block 保留原始入口块。
pub struct VmContext {
    pub entry_va: u64,
    pub mapping: MappedAddress,
    pub first_block: DecodedBlock,
    pub blocks: Vec<DecodedBlock>,
    pub initialization: Value,
    pub local_ir: String,
    pub local_ir_path: PathBuf,
    pub bitcode_path: PathBuf,
    pub output_dir: PathBuf,
}

/// 函数分析的资源限制与已验证检查点；预算耗尽不能作为函数结束。
pub struct FunctionAnalysisOptions {
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub max_bytes: usize,
    pub resume_from: Option<PathBuf>,
}
impl Default for FunctionAnalysisOptions {
    fn default() -> Self {
        Self {
            max_blocks: 512,
            max_instructions: 32768,
            max_bytes: 131072,
            resume_from: None,
        }
    }
}

impl VmSession {
    pub fn open(root: &Path, module: &Path, output_root: &Path) -> Result<Self> {
        let module_path = module.canonicalize()?;
        let module_bytes = fs::read(&module_path)?;
        let image = PeImage::parse(&module_bytes)?;
        fs::create_dir_all(output_root)?;
        Ok(Self {
            root: root.canonicalize()?,
            module_path,
            module_bytes,
            image,
            output_root: output_root.canonicalize()?,
        })
    }

    /// 以原生 State/guest memory 为状态机，继续收集 Context；不以内部 CALL 判完成。
    pub fn init_vm_context(&self, vm_entry: u64) -> Result<VmContext> {
        self.walk_vm(vm_entry, None)
    }

    pub fn analyze_vm_function(
        &self,
        vm_entry: u64,
        options: &FunctionAnalysisOptions,
    ) -> Result<VmContext> {
        self.walk_vm(vm_entry, Some(options))
    }

    fn walk_vm(
        &self,
        vm_entry: u64,
        options: Option<&FunctionAnalysisOptions>,
    ) -> Result<VmContext> {
        if self.image.bitness != 64 {
            bail!("CONTEXT_POLICY_UNSUPPORTED: 当前完成判定要求 AMD64 TVM 画像");
        }
        let mapping = self
            .image
            .map_executable_va(vm_entry, self.module_bytes.len())?;
        let output_dir = self.output_root.join(format!("{vm_entry:x}"));
        fs::create_dir_all(&output_dir)?;
        fs::write(
            output_dir.join("context.json"),
            b"{\"status\":\"initializing\"}\n",
        )?;
        let mut blocks: Vec<DecodedBlock> = Vec::new();
        let mut chain = Vec::new();
        let mut history = Vec::new();
        let mut visited = std::collections::BTreeSet::new();
        let mut target = vm_entry;
        let mut transitions = Vec::new();
        let mut image_facts = std::collections::BTreeMap::<u64, Vec<u8>>::new();
        let mut vip = VipTracker::default();
        let mut graph = SemanticGraph::default();
        if let Some(checkpoint) = options.and_then(|options| options.resume_from.as_ref()) {
            let saved: Value =
                serde_json::from_slice(&fs::read(checkpoint.join("state-machine.json"))?)?;
            let digest = hex::encode(Sha256::digest(&self.module_bytes));
            let facts: Value = serde_json::from_slice(&fs::read(
                checkpoint
                    .join("rounds")
                    .join(format!(
                        "{:02}",
                        saved["blocks"].as_array().context("检查点无 blocks")?.len() - 1
                    ))
                    .join("image-facts.json"),
            )?)?;
            anyhow::ensure!(
                facts["input_sha256"] == digest,
                "CHECKPOINT_MODULE_MISMATCH"
            );
            anyhow::ensure!(
                saved["entry"].as_u64() == Some(vm_entry),
                "CHECKPOINT_ENTRY_MISMATCH"
            );
            blocks = serde_json::from_value(saved["blocks"].clone())?;
            // 检查每块原始字节，拒绝把其他模块或已改变映像的状态带入当前分析。
            for block in &blocks {
                let mapped = self
                    .image
                    .map_executable_va(block.start_pc, self.module_bytes.len())?;
                let bytes: Vec<u8> = block
                    .instructions
                    .iter()
                    .map(|instruction| hex::decode(&instruction.bytes))
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .concat();
                anyhow::ensure!(
                    self.module_bytes[mapped.file_offset..mapped.file_offset + bytes.len()]
                        == bytes,
                    "CHECKPOINT_BYTES_MISMATCH: 0x{:X}",
                    block.start_pc
                );
                chain.push(json!({"pc":format!("0x{:x}",block.start_pc),"bytes":hex::encode(&bytes),
                    "instructions":block.instructions.iter().map(|item|json!({"pc":format!("0x{:x}",item.instruction.pc),"length":item.instruction.length})).collect::<Vec<_>>()}));
            }
            history = serde_json::from_slice(&fs::read(
                checkpoint.join("initialization.progress.json"),
            )?)?;
            transitions = serde_json::from_value(saved["transitions"].clone())?;
            vip = serde_json::from_value(saved["vip"].clone())?;
            graph = serde_json::from_value(saved["semantic_graph"].clone())?;
            for node in graph
                .nodes
                .values()
                .filter(|node| node["status"] == "analyzed")
            {
                visited.insert(serde_json::from_value::<SemanticAddress>(
                    node["semantic_address"].clone(),
                )?);
            }
            for fact in facts["facts"].as_array().context("检查点快照缺失")? {
                image_facts.insert(
                    parse_address(&fact["address"])?,
                    hex::decode(fact["bytes"].as_str().context("快照字节缺失")?)?,
                );
            }
            target = parse_address(&saved["initialization"]["next_target"])?;
        }
        let max_blocks = options.map_or(32, |options| options.max_blocks);
        let max_instructions = options.map_or(4096, |options| options.max_instructions);
        let max_bytes = options.map_or(16384, |options| options.max_bytes);
        let mut worker = Worker::spawn(&self.root.join("toolchains/bin/nereus-remill-worker.exe"))?;
        for round in blocks.len()..max_blocks {
            eprintln!(
                "NeREUS block {round}: RIP=0x{target:X}, VIP=0x{:X}",
                vip.current.unwrap_or(0)
            );
            let mut semantic_address = SemanticAddress {
                eip: target,
                vip: vip.current,
            };
            if !visited.insert(semantic_address.clone()) {
                return initialization_error(
                    &output_dir,
                    "INITIALIZATION_CYCLE",
                    target,
                    "初始化尚未完成且重复到达同一地址",
                    &history,
                );
            }
            let next_mapping = match self
                .image
                .map_executable_va(target, self.module_bytes.len())
            {
                Ok(mapping) => mapping,
                Err(error) => {
                    return initialization_error(
                        &output_dir,
                        "BRANCH_TARGET_UNREACHABLE",
                        target,
                        &error.to_string(),
                        &history,
                    );
                }
            };
            let count = next_mapping.available_raw_bytes.min(4096);
            let window =
                &self.module_bytes[next_mapping.file_offset..next_mapping.file_offset + count];
            let block =
                match nereus_x86::decode_basic_block(Architecture::Amd64, target, window, 512) {
                    Ok(block) => block,
                    Err(error) => {
                        return initialization_error(
                            &output_dir,
                            "SUCCESSOR_DECODE_FAILED",
                            target,
                            &error.to_string(),
                            &history,
                        );
                    }
                };
            let bytes = hex::encode(&window[..block.byte_length]);
            chain.push(json!({"pc": format!("0x{target:x}"), "bytes": bytes,
                "instructions": block.instructions.iter().map(|item| json!({"pc": format!("0x{:x}", item.instruction.pc), "length": item.instruction.length})).collect::<Vec<_>>() }));
            blocks.push(block);
            let byte_length: usize = blocks.iter().map(|block| block.byte_length).sum();
            let instruction_count: usize =
                blocks.iter().map(|block| block.instructions.len()).sum();
            if byte_length > max_bytes || instruction_count > max_instructions {
                return initialization_error(
                    &output_dir,
                    "INITIALIZATION_BUDGET_EXCEEDED",
                    target,
                    "合并字节/指令数超出预算",
                    &history,
                );
            }
            let round_dir = output_dir.join(format!("rounds/{round:02}"));
            fs::create_dir_all(&round_dir)?;
            let mut bytes = String::new();
            let mut lengths = Vec::new();
            let mut pcs = Vec::new();
            let mut ends = Vec::new();
            for item in &chain {
                bytes.push_str(item["bytes"].as_str().context("内部字节缺失")?);
                for instruction in item["instructions"].as_array().context("内部指令缺失")? {
                    lengths.push(instruction["length"].clone());
                    pcs.push(instruction["pc"].clone());
                }
                ends.push(lengths.len());
            }
            // 从入口重新提升已确认链，共用一个 State 和 memory token；不会拼接互不关联的块函数。
            let lift_request = json!({
                "op": "lift-block", "architecture": "amd64", "pc": format!("0x{vm_entry:x}"),
                "bytes": bytes, "instruction_lengths": lengths, "instruction_pcs": pcs,
                "block_end_indices": ends, "output_dir": round_dir,
                "semantics_dir": self.root.join("toolchains/remill-install/share/remill/17/semantics")
            });
            let lifted = worker.request(lift_request.clone())?;
            let function = lifted["function_name"]
                .as_str()
                .context("worker 没有返回函数名")?;
            let prepared = match prepare_block_il_with_snapshot(
                &self.root,
                &round_dir,
                function,
                Some((&self.image, &self.module_bytes)),
                &mut image_facts,
                None,
            ) {
                Ok(prepared) => prepared,
                Err(error) => {
                    return initialization_error(
                        &output_dir,
                        "STATE_MACHINE_LIFT_FAILED",
                        target,
                        &error.to_string(),
                        &history,
                    );
                }
            };
            let mut evidence = prepared["optimization"]["initialization"].clone();
            let caller_return = options.is_some()
                && blocks
                    .last()
                    .is_some_and(|block| block.terminator == "Return")
                && prepared["optimization"]["function_return"]["is_caller_return"] == true;
            let return_classification = json!({"kind":"return","target_set_complete":true,
                "evidence":prepared["optimization"]["function_return"]});
            let classification = if caller_return {
                &return_classification
            } else {
                &prepared["branch"]
            };
            let previous_vip = vip.current;
            vip.update(&evidence, &prepared["optimization"]);
            if semantic_address.vip.is_none() && previous_vip.is_none() {
                semantic_address.vip = vip.stream_base;
            }
            graph.enter(
                &semantic_address,
                vip.current,
                classification,
                &evidence,
                blocks.last().context("没有基本块")?,
                blocks
                    .iter()
                    .take(blocks.len() - 1)
                    .map(|block| block.instructions.len())
                    .sum(),
            );
            if let Some(seed) = vip.stream_base {
                let trace_dir = round_dir.join("instruction-vip-trace");
                fs::create_dir_all(&trace_dir)?;
                let mut request = lift_request.clone();
                request["trace_instruction_vip"] = true.into();
                request["trace_seed_register"] = vip
                    .evidence
                    .first()
                    .map(|evidence| evidence["register_at_observation"].clone())
                    .unwrap_or(Value::Null);
                request["output_dir"] = serde_json::to_value(&trace_dir)?;
                let trace_lifted = worker.request(request)?;
                let trace_function = trace_lifted["function_name"]
                    .as_str()
                    .context("trace 函数名缺失")?;
                let trace_prepared = prepare_block_il_with_snapshot(
                    &self.root,
                    &trace_dir,
                    trace_function,
                    Some((&self.image, &self.module_bytes)),
                    &mut image_facts,
                    Some(
                        json!({"stream_base":format!("0x{seed:x}"),"cursor_slot_from_entry_rsp":vip.cursor_slot_from_entry_rsp}),
                    ),
                )?;
                let rows = trace_prepared["optimization"]["instruction_vips"]
                    .as_array()
                    .context("逐指令 VIP 记录缺失")?;
                let expected: usize = blocks.iter().map(|block| block.instructions.len()).sum();
                if rows.len() != expected {
                    bail!(
                        "INSTRUCTION_VIP_TRACE_INCOMPLETE: expected {expected}, got {}",
                        rows.len()
                    );
                }
                graph.apply_instruction_vips(rows, vip.current)?;
                let current_start: usize = blocks
                    .iter()
                    .take(blocks.len() - 1)
                    .map(|block| block.instructions.len())
                    .sum();
                let entry_vip = parse_address(&rows[current_start]["vip"])?;
                semantic_address.vip = (entry_vip != 0).then_some(entry_vip);
                fs::write(
                    output_dir.join("instruction-vips.json"),
                    serde_json::to_vec_pretty(rows)?,
                )?;
            }
            if classification["kind"] == "direct"
                && evidence["unique_target_resolved"] != true
                && let Some(address) = classification["targets"]
                    .as_array()
                    .and_then(|targets| targets.first())
            {
                evidence["unique_target_resolved"] = true.into();
                evidence["next_target"] = address.clone();
                evidence["target_resolution"] = "SMT-finite-range-proof".into();
            }
            if let Some(targets) = classification["targets"].as_array()
                && classification["target_set_complete"] == true
            {
                for address in targets {
                    let next = parse_address(address)?;
                    let condition =
                        classification["conditions"]
                            .as_array()
                            .and_then(|conditions| {
                                conditions
                                    .iter()
                                    .find(|condition| condition["target"] == *address)
                            });
                    graph.edge(
                        &semantic_address,
                        SemanticAddress {
                            eip: next,
                            vip: vip.current,
                        },
                        classification["kind"].as_str().unwrap_or("unresolved"),
                        condition,
                    );
                }
            }
            let current_block = blocks.last().context("没有基本块")?;
            if evidence["unique_target_resolved"] == true {
                let next = parse_address(&evidence["next_target"])?;
                let next_mapping = self.image.map_executable_va(next, self.module_bytes.len());
                let is_call = matches!(current_block.terminator.as_str(), "Call" | "IndirectCall");
                let internal = next_mapping
                    .as_ref()
                    .is_ok_and(|mapped| mapped.section == mapping.section);
                let transition = json!({"source": format!("0x{target:x}"), "target": format!("0x{next:x}"),
                    "native_kind": current_block.terminator, "source_section": next_mapping_for_block(&self.image, target, self.module_bytes.len())?,
                    "target_section": next_mapping.as_ref().ok().map(|value| &value.section),
                    "semantics": if is_call && internal { "push-return-address-and-internal-jump" } else if is_call { "external-call-boundary" } else { "native-control-transfer" },
                    "return_address_pushed": is_call, "fallthrough": current_block.fallthrough});
                transitions.push(transition.clone());
                evidence["transition"] = transition;
                if is_call {
                    // TVM 段内 CALL 是状态机边：保留压栈，不能用 guest 保存完成作终止条件。
                    evidence["complete"] = false.into();
                    if !internal {
                        history.push(json!({"round": round, "block_entry":format!("0x{target:x}"), "initialization":evidence}));
                        return initialization_error(
                            &output_dir,
                            "EXTERNAL_CALL_DURING_INITIALIZATION",
                            target,
                            "Context 未完成，CALL 目标不在当前 VM 区域；需要调用摘要",
                            &history,
                        );
                    }
                }
            }
            history.push(
                json!({"round": round, "block_entry": format!("0x{target:x}"),
                "merged_block_count": blocks.len(), "semantic_address":semantic_address,"output_vip":vip.current,
                "branch":classification,"initialization": evidence}),
            );
            fs::write(
                output_dir.join("initialization.progress.json"),
                serde_json::to_vec_pretty(&history)?,
            )?;
            // 每轮都发布最新可审查 IR 与机器状态；失败时也不回退到旧的四块假完成产物。
            for name in [
                "block.raw.bc",
                "block.raw.ll",
                "block.extracted.bc",
                "block.lifted.bc",
                "block.lifted.ll",
                "block.optimized.bc",
                "block.optimized.ll",
            ] {
                fs::copy(round_dir.join(name), output_dir.join(name))?;
            }
            let listing = blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .map(|item| {
                    format!(
                        "{:016X}  {:<30}  {}",
                        item.instruction.pc, item.bytes, item.instruction.text
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(output_dir.join("block.asm"), listing)?;
            fs::write(
                output_dir.join("state-machine.json"),
                serde_json::to_vec_pretty(&json!({
                    "entry": vm_entry, "stage": evidence["stage"], "initialization_complete": false,
                    "blocks": blocks, "transitions": transitions, "initialization": evidence, "prepared": prepared,
                    "vip":vip,"semantic_graph":graph,
                    "observation_model": "normal-completion-state-and-guest-memory"
                }))?,
            )?;
            fs::write(
                output_dir.join("semantic-graph.json"),
                serde_json::to_vec_pretty(&graph)?,
            )?;
            graph_export::export(&self.root, &output_dir, &graph)?;
            if caller_return {
                let result = json!({"status":"returned","interface":"analyze_vm_function",
                    "entry":format!("0x{vm_entry:X}"),"native_ret":format!("0x{:X}",current_block.instructions.last().context("RET 缺失")?.instruction.pc),
                    "vip":format!("0x{:X}",vip.current.unwrap_or(0)),"blocks":blocks.len(),
                    "return_proof":prepared["optimization"]["function_return"],"initialization_complete":false,
                    "input_sha256":hex::encode(Sha256::digest(&self.module_bytes))});
                fs::write(
                    output_dir.join("function-analysis.json"),
                    serde_json::to_vec_pretty(&result)?,
                )?;
                fs::write(
                    output_dir.join("context.json"),
                    serde_json::to_vec_pretty(&result)?,
                )?;
                return Ok(VmContext {
                    entry_va: vm_entry,
                    mapping,
                    first_block: blocks[0].clone(),
                    blocks,
                    initialization: evidence,
                    local_ir: fs::read_to_string(output_dir.join("block.optimized.ll"))?,
                    local_ir_path: output_dir.join("block.optimized.ll"),
                    bitcode_path: output_dir.join("block.optimized.bc"),
                    output_dir,
                });
            }
            if classification["kind"] == "conditional" {
                return initialization_error(
                    &output_dir,
                    "VJCC_FRONTIER",
                    target,
                    "发现有限双目标条件分支，已保留条件与两条语义边；不得按单路径合并",
                    &history,
                );
            }
            if evidence["complete"] == true && options.is_none() {
                let handoff = parse_address(&evidence["handoff_target"])?;
                if let Err(error) = self
                    .image
                    .map_executable_va(handoff, self.module_bytes.len())
                {
                    return initialization_error(
                        &output_dir,
                        "HANDOFF_TARGET_UNREACHABLE",
                        handoff,
                        &error.to_string(),
                        &history,
                    );
                }
                let bytecode = parse_address(&evidence["bytecode_address"])?;
                // 当前 TVM 实例字节码位于映像的可执行原始区域；其他布局需要独立画像规则。
                if let Err(error) = self
                    .image
                    .map_executable_va(bytecode, self.module_bytes.len())
                {
                    return initialization_error(
                        &output_dir,
                        "BYTECODE_ADDRESS_UNMAPPED",
                        bytecode,
                        &error.to_string(),
                        &history,
                    );
                }
                for name in [
                    "block.raw.bc",
                    "block.raw.ll",
                    "block.extracted.bc",
                    "block.lifted.bc",
                    "block.lifted.ll",
                    "block.optimized.bc",
                    "block.optimized.ll",
                ] {
                    fs::copy(round_dir.join(name), output_dir.join(name))?;
                }
                let listing = blocks
                    .iter()
                    .map(|block| {
                        block
                            .instructions
                            .iter()
                            .map(|item| {
                                format!(
                                    "{:016X}  {:<30}  {}",
                                    item.instruction.pc, item.bytes, item.instruction.text
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n");
                fs::write(output_dir.join("block.asm"), listing)?;
                let metadata = json!({"interface": "init_vm_context", "status": "complete", "module": self.module_path,
                    "entry_va": vm_entry, "input_sha256": hex::encode(Sha256::digest(&self.module_bytes)),
                    "image_base": self.image.image_base, "mapping": mapping, "blocks": blocks,
                    "lifted_block_count": blocks.len(), "successors_followed": blocks.len() > 1,
                    "initialization": evidence, "history": history, "prepared": prepared,
                    "handoff_callee_followed": false, "observation_model": "normal-completion-state-and-guest-memory"});
                fs::write(
                    output_dir.join("context.json"),
                    serde_json::to_vec_pretty(&metadata)?,
                )?;
                let old_error = output_dir.join("initialization.error.json");
                if old_error.is_file() {
                    fs::remove_file(old_error)?;
                }
                let local_ir_path = output_dir.join("block.optimized.ll");
                return Ok(VmContext {
                    entry_va: vm_entry,
                    mapping,
                    first_block: blocks[0].clone(),
                    blocks,
                    initialization: evidence,
                    local_ir: fs::read_to_string(&local_ir_path)?,
                    local_ir_path,
                    bitcode_path: output_dir.join("block.optimized.bc"),
                    output_dir,
                });
            }
            if evidence["unique_target_resolved"] != true {
                return initialization_error(
                    &output_dir,
                    "BRANCH_TARGET_UNRESOLVED",
                    target,
                    "Context 未完成且块末目标不能唯一计算",
                    &history,
                );
            }
            let last = blocks.last().context("没有基本块")?;
            if last.terminator == "Exception" || last.terminator == "Interrupt" {
                return initialization_error(
                    &output_dir,
                    "INITIALIZATION_EARLY_EXIT",
                    target,
                    "Context 未完成即返回或出现异常边界",
                    &history,
                );
            }
            target = parse_address(&evidence["next_target"])?;
        }
        initialization_error(
            &output_dir,
            "INITIALIZATION_BUDGET_EXCEEDED",
            target,
            &format!("合并达到 {max_blocks} 个基本块上限；保留前沿，不视为 RET"),
            &history,
        )
    }

    pub fn lift_entry_block(&self, vm_entry: u64) -> Result<VmContext> {
        let mapping = self
            .image
            .map_executable_va(vm_entry, self.module_bytes.len())?;
        let architecture = if self.image.bitness == 64 {
            Architecture::Amd64
        } else {
            Architecture::X86
        };
        let byte_count = mapping.available_raw_bytes.min(4096);
        let window = &self.module_bytes[mapping.file_offset..mapping.file_offset + byte_count];
        let first_block = nereus_x86::decode_basic_block(architecture, vm_entry, window, 512)?;
        let output_dir = self.output_root.join(format!("{vm_entry:x}"));
        fs::create_dir_all(&output_dir)?;
        let bytes = &window[..first_block.byte_length];
        fs::write(output_dir.join("block.bin"), bytes)?;
        let assembly = first_block
            .instructions
            .iter()
            .map(|item| {
                format!(
                    "{:016X}  {:<30}  {}",
                    item.instruction.pc, item.bytes, item.instruction.text
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(output_dir.join("block.asm"), format!("{assembly}\n"))?;
        let lengths: Vec<_> = first_block
            .instructions
            .iter()
            .map(|item| item.instruction.length)
            .collect();
        let mut worker = Worker::spawn(&self.root.join("toolchains/bin/nereus-remill-worker.exe"))?;
        let lifted = worker.request(json!({
            "op": "lift-block", "architecture": if self.image.bitness == 64 { "amd64" } else { "x86" },
            "pc": format!("0x{vm_entry:x}"), "bytes": hex::encode(bytes), "instruction_lengths": lengths,
            "output_dir": output_dir, "semantics_dir": self.root.join("toolchains/remill-install/share/remill/17/semantics")
        }))?;
        let raw_llvm = nereus_llvm_support::verify_bitcode(&output_dir.join("block.raw.bc"))?;
        let function = lifted["function_name"]
            .as_str()
            .context("worker 没有返回函数名")?;
        let prepared = prepare_block_il(&self.root, &output_dir, function)?;
        let local_ir_path = output_dir.join("block.optimized.ll");
        let bitcode_path = output_dir.join("block.optimized.bc");
        let local_ir = fs::read_to_string(&local_ir_path)?;
        let metadata = json!({
            "interface": "lift_entry_block", "module": self.module_path,
            "input_sha256": hex::encode(Sha256::digest(&self.module_bytes)),
            "entry_va": vm_entry, "image_base": self.image.image_base, "mapping": mapping,
            "first_block": first_block, "remill": lifted, "raw_llvm": raw_llvm, "prepared": prepared,
            "lifted_block_count": 1, "successors_followed": false,
            "vm_state_semantics_analyzed": false
        });
        fs::write(
            output_dir.join("context.json"),
            serde_json::to_vec_pretty(&metadata)?,
        )?;
        Ok(VmContext {
            entry_va: vm_entry,
            mapping,
            blocks: vec![first_block.clone()],
            initialization: prepared["optimization"]["initialization"].clone(),
            first_block,
            local_ir,
            local_ir_path,
            bitcode_path,
            output_dir,
        })
    }
}

fn parse_address(value: &Value) -> Result<u64> {
    let text = value.as_str().context("worker 未提供地址")?;
    Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

fn next_mapping_for_block(image: &PeImage, address: u64, length: usize) -> Result<String> {
    Ok(image.map_executable_va(address, length)?.section)
}

fn initialization_error<T>(
    directory: &Path,
    code: &str,
    block: u64,
    message: &str,
    history: &[Value],
) -> Result<T> {
    let diagnostic = json!({"status": "failed", "code": code, "block": format!("0x{block:x}"), "message": message, "history": history});
    fs::write(
        directory.join("initialization.error.json"),
        serde_json::to_vec_pretty(&diagnostic)?,
    )?;
    // 不留下上一轮运行的成功状态；失败详情携带当前可定位的诊断。
    fs::write(
        directory.join("context.json"),
        serde_json::to_vec_pretty(&diagnostic)?,
    )?;
    bail!("{code}: block=0x{block:x}: {message}")
}

fn run_llvm(program: &Path, arguments: &[&std::ffi::OsStr]) -> Result<()> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("无法执行 {}", program.display()))?;
    if !output.status.success() {
        bail!(
            "{} 失败：{}",
            program.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn prepare_block_il(root: &Path, output: &Path, function: &str) -> Result<Value> {
    prepare_block_il_with_snapshot(
        root,
        output,
        function,
        None,
        &mut std::collections::BTreeMap::new(),
        None,
    )
}

fn prepare_block_il_with_snapshot(
    root: &Path,
    output: &Path,
    function: &str,
    snapshot: Option<(&PeImage, &[u8])>,
    facts: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    trace_config: Option<Value>,
) -> Result<Value> {
    let local: Value = serde_json::from_slice(&fs::read(root.join("toolchains/local.json"))?)?;
    let bin = PathBuf::from(local["llvm_root"].as_str().context("未配置 LLVM")?).join("bin");
    let raw = output.join("block.raw.bc");
    let extracted = output.join("block.extracted.bc");
    let lifted = output.join("block.lifted.bc");
    let il = output.join("block.lifted.ll");
    let function_arg = format!("--func={function}");
    run_llvm(
        &bin.join("llvm-extract.exe"),
        &[
            function_arg.as_ref(),
            "--recursive".as_ref(),
            raw.as_os_str(),
            "-o".as_ref(),
            extracted.as_os_str(),
        ],
    )?;
    // 只展开当前块的指令语义，内存访问及末尾控制转移仍显式保留。
    let passes =
        "internalize,always-inline,function(sroa,mem2reg,instcombine,simplifycfg),globaldce";
    let pass_arg = format!("-passes={passes}");
    let public_arg = format!("-internalize-public-api-list={function}");
    run_llvm(
        &bin.join("opt.exe"),
        &[
            pass_arg.as_ref(),
            public_arg.as_ref(),
            "-verify-each".as_ref(),
            extracted.as_os_str(),
            "-o".as_ref(),
            lifted.as_os_str(),
        ],
    )?;
    run_llvm(
        &bin.join("llvm-dis.exe"),
        &[lifted.as_os_str(), "-o".as_ref(), il.as_os_str()],
    )?;
    let reference = nereus_llvm_support::verify_bitcode(&lifted)?;
    let mut optimizer = Worker::spawn(&root.join("toolchains/bin/nereus-remill-worker.exe"))?;
    let mut optimization = Value::Null;
    let mut previous = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut iteration_history = Vec::new();
    let mut converged = false;
    let mut stop_reason = "iteration-budget-exhausted";
    // 上限只保护资源；达到上限或出现振荡都不能当成成功的稳定状态。
    const SNAPSHOT_ITERATION_BUDGET: usize = 256;
    for iteration in 1..=SNAPSHOT_ITERATION_BUDGET {
        let input_facts = facts.clone();
        optimization=optimizer.request(json!({"op":"optimize-local","input_bitcode":lifted,
            "output_dir":output,"function_name":function,
            "image_facts":facts.iter().map(|(address,bytes)|json!({"address":format!("0x{address:x}"),"bytes":hex::encode(bytes)})).collect::<Vec<_>>(),
            "vip_trace":trace_config}))?;
        if optimization["converged"] != true {
            stop_reason = "worker-not-converged";
            iteration_history.push(json!({"iteration":iteration,"worker_converged":false,
                "worker_stop_reason":optimization["stop_reason"]}));
            break;
        }
        if let Some((image, bytes)) = snapshot {
            if let Some(exits) = optimization["initialization"]["exits"].as_array() {
                for exit in exits {
                    if let Some(reads) = exit["blocking_memory_reads"].as_array() {
                        for read in reads {
                            let (Some(address), Some(width)) =
                                (read["address"].as_str(), read["width_bits"].as_u64())
                            else {
                                continue;
                            };
                            let address =
                                u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
                            if facts
                                .get(&address)
                                .is_some_and(|bytes| bytes.len() >= (width / 8) as usize)
                            {
                                continue;
                            }
                            if let Ok(data) =
                                image.readonly_snapshot(bytes, address, (width / 8) as usize)
                            {
                                facts.insert(address, data);
                            }
                        }
                    }
                }
            }
            if let Some(reads) = optimization["context_read_dependencies"].as_array() {
                for read in reads {
                    let (Some(address), Some(width)) =
                        (read["address"].as_str(), read["width_bits"].as_u64())
                    else {
                        continue;
                    };
                    let address = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
                    if facts
                        .get(&address)
                        .is_some_and(|bytes| bytes.len() >= (width / 8) as usize)
                    {
                        continue;
                    }
                    if let Ok(data) = image.readonly_snapshot(bytes, address, (width / 8) as usize)
                    {
                        facts.insert(address, data);
                    }
                }
            }
        }
        // 状态只包含语义证据，不包含每次请求都会变化的计数、request_id 和历史。
        // facts 单调累积；每轮从未裁剪的 lifted IR 重算，避免丢失原始数据依赖。
        let ir = fs::read(output.join("block.optimized.ll"))?;
        let state = json!({"initialization":optimization["initialization"],
            "branch":optimization["branch_analysis"],
            "context_reads":optimization["context_read_dependencies"],
            "instruction_vips":optimization["instruction_vips"],"facts":facts});
        let ir_hash = hex::encode(Sha256::digest(&ir));
        let state_hash = hex::encode(Sha256::digest(serde_json::to_vec(&state)?));
        let ir_changed = previous.as_ref().is_none_or(|(old_ir, _)| old_ir != &ir);
        let state_changed = previous
            .as_ref()
            .is_none_or(|(_, old_state)| old_state != &state);
        let facts_changed = *facts != input_facts;
        iteration_history.push(json!({"iteration":iteration,"ir_sha256":ir_hash,
            "state_sha256":state_hash,"ir_changed":ir_changed,"state_changed":state_changed,
            "facts_changed":facts_changed,"worker_iterations":optimization["iterations"],
            "worker_converged":true}));
        // 新发现的事实必须确实被下一轮消费，不能拿旧事实算出的 IR 宣称收敛。
        if !ir_changed && !state_changed && !facts_changed {
            converged = true;
            stop_reason = "fixed-point";
            break;
        }
        if !seen.insert((ir_hash, state_hash)) {
            stop_reason = "optimization-cycle";
            break;
        }
        previous = Some((ir, state));
    }
    let progress = json!({"converged":converged,"stop_reason":stop_reason,
        "iteration_budget":SNAPSHOT_ITERATION_BUDGET,"iterations":iteration_history.len(),
        "history":iteration_history,"worker":optimization});
    fs::write(
        output.join("optimization.progress.json"),
        serde_json::to_vec_pretty(&progress)?,
    )?;
    if !converged {
        bail!(
            "OPTIMIZATION_NOT_CONVERGED: {stop_reason}; 诊断：{}",
            output.join("optimization.progress.json").display()
        );
    }
    let classification = branch::classify(root, output, &optimization["branch_analysis"])?;
    fs::write(
        output.join("branch.classification.json"),
        serde_json::to_vec_pretty(&classification)?,
    )?;
    let snapshot_evidence = json!({"facts":facts.iter().map(|(address,bytes)|json!({"address":format!("0x{address:x}"),"bytes":hex::encode(bytes)})).collect::<Vec<_>>(),
        "input_sha256":snapshot.map(|(_,bytes)|hex::encode(Sha256::digest(bytes))),
        "preferred_image_base":snapshot.map(|(image,_)|image.image_base),
        "preconditions":if facts.is_empty(){Vec::<&str>::new()}else{vec!["PE-preferred-base-readonly-image-equals-file-snapshot","entry-stack-disjoint-from-image"]}});
    fs::write(
        output.join("image-facts.json"),
        serde_json::to_vec_pretty(&snapshot_evidence)?,
    )?;
    let optimized_bc = output.join("block.optimized.bc");
    let optimized_ir = output.join("block.optimized.ll");
    Ok(
        json!({"passes": passes, "reference_ir": il, "reference_bitcode": lifted,
            "reference_llvm": reference, "llvm_ir": optimized_ir, "bitcode": optimized_bc,
            "llvm": nereus_llvm_support::verify_bitcode(&optimized_bc)?, "optimization": optimization,
            "fixed_point":progress,
            "branch":classification,"image_snapshot":snapshot_evidence,
            "nir_normalized": false}),
    )
}
