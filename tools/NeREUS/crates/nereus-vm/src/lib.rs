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

/// 会话绑定模块和提升环境；入口地址是 init_vm_context 唯一的调用参数。
pub struct VmSession {
    root: PathBuf,
    module_path: PathBuf,
    module_bytes: Vec<u8>,
    image: PeImage,
    output_root: PathBuf,
}

/// 为后续语义分析保留首块和局部 IR，不预设 VIP/VSP 或跟随后继。
pub struct VmContext {
    pub entry_va: u64,
    pub mapping: MappedAddress,
    pub first_block: DecodedBlock,
    pub local_ir: String,
    pub local_ir_path: PathBuf,
    pub bitcode_path: PathBuf,
    pub output_dir: PathBuf,
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

    pub fn init_vm_context(&self, vm_entry: u64) -> Result<VmContext> {
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
            "interface": "init_vm_context", "module": self.module_path,
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
            first_block,
            local_ir,
            local_ir_path,
            bitcode_path,
            output_dir,
        })
    }
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
    let optimization = optimizer.request(json!({
        "op": "optimize-local", "input_bitcode": lifted,
        "output_dir": output, "function_name": function
    }))?;
    let optimized_bc = output.join("block.optimized.bc");
    let optimized_ir = output.join("block.optimized.ll");
    Ok(
        json!({"passes": passes, "reference_ir": il, "reference_bitcode": lifted,
            "reference_llvm": reference, "llvm_ir": optimized_ir, "bitcode": optimized_bc,
            "llvm": nereus_llvm_support::verify_bitcode(&optimized_bc)?, "optimization": optimization,
            "nir_normalized": false}),
    )
}
