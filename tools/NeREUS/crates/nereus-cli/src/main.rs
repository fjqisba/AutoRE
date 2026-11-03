use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nereus_core::Architecture;
use nereus_remill::Worker;
use nereus_vm::{FunctionAnalysisOptions, VmSession, prepare_block_il};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
#[command(
    name = "nereus",
    version,
    about = "NeREUS 工具链诊断与指令提升基础设施"
)]
struct Cli {
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 沿可证明的 VM 状态机分析到调用者 RET；保留未解析或条件前沿。
    AnalyzeVmFunction {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        entry: String,
        #[arg(long, default_value = "temp_data/vm-function")]
        out: PathBuf,
        #[arg(long, default_value_t = 512)]
        max_blocks: usize,
        #[arg(long)]
        resume_from: Option<PathBuf>,
        /// 路径约束：指定首次 64 位 guest 读取为零，保留原读取和假设。
        #[arg(long)]
        assume_load64_zero: Vec<String>,
        /// 路径约束：指定首次 64 位 guest 读取非零，不替换为代表值 1。
        #[arg(long)]
        assume_load64_nonzero: Vec<String>,
    },
    /// 沿可计算分支合并初始化逻辑，完成后输出 IR；未完成且目标不明则返回错误。
    #[command(alias = "init_vm_context")]
    InitVmContext {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        entry: String,
        #[arg(long, default_value = "temp_data/vm-context")]
        out: PathBuf,
    },
    /// 检查实际 Rust、LLVM 和 Remill worker 调用链。
    Doctor,
    /// 提升单条原生指令并用独立 Rust LLVM 绑定验证 bitcode。
    LiftInstruction {
        #[arg(long, default_value = "amd64")]
        arch: String,
        #[arg(long, default_value = "0x140001000")]
        pc: String,
        #[arg(long)]
        bytes: String,
        #[arg(long)]
        out: PathBuf,
    },
    VerifyBitcode {
        path: PathBuf,
    },
    /// 按 PE 首选 ImageBase 映射 VA，提取并提升一个原生基本块。
    LiftPeBlock {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        va: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 4096)]
        max_bytes: usize,
        #[arg(long, default_value_t = 512)]
        max_instructions: usize,
    },
}

fn find_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(root) = explicit {
        return Ok(root.canonicalize()?);
    }
    if let Some(root) = std::env::var_os("NEREUS_ROOT") {
        return Ok(PathBuf::from(root));
    }
    for parent in std::env::current_dir()?.ancestors() {
        if parent.join("toolchains/versions.lock.json").is_file() {
            return Ok(parent.to_path_buf());
        }
    }
    bail!("未找到 NeREUS 目录，请指定 --root")
}

fn version(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("无法启动 {program}"))?;
    if !output.status.success() {
        bail!("{program} 返回 {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn verify_manifest(root: &Path) -> Result<Value> {
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("toolchains/semantics.manifest.json"))?)?;
    let lock: Value =
        serde_json::from_slice(&fs::read(root.join("toolchains/versions.lock.json"))?)?;
    if manifest["remill_revision"] != lock["remill"]["revision"] || manifest["llvm"] != lock["llvm"]
    {
        bail!("SEMANTICS_VERSION_MISMATCH: manifest 与锁定文件不一致");
    }
    let verify_hash = |path: &Path, expected: &Value| -> Result<()> {
        let actual = hex::encode(Sha256::digest(fs::read(path)?));
        if Some(actual.as_str()) != expected.as_str() {
            bail!(
                "SEMANTICS_VERSION_MISMATCH: 文件哈希不匹配 {}",
                path.display()
            );
        }
        Ok(())
    };
    verify_hash(
        &root.join("toolchains/bin/nereus-remill-worker.exe"),
        &manifest["worker_sha256"],
    )?;
    let semantics = manifest["semantics"]
        .as_array()
        .context("manifest 缺少 semantics 列表")?;
    for item in semantics {
        let name = item["name"].as_str().context("semantics 项缺少 name")?;
        verify_hash(
            &root
                .join("toolchains/remill-install/share/remill/17/semantics")
                .join(name),
            &item["sha256"],
        )?;
    }
    Ok(json!({"verified": true, "semantics_files": semantics.len()}))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = find_root(cli.root)?;
    let worker_path = root.join("toolchains/bin/nereus-remill-worker.exe");
    let result = match cli.command {
        Commands::AnalyzeVmFunction {
            input,
            entry,
            out,
            max_blocks,
            resume_from,
            assume_load64_zero,
            assume_load64_nonzero,
        } => {
            let _integrity = verify_manifest(&root)?;
            let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16)?;
            let session = VmSession::open(&root, &input, &out)?;
            let mut conditions = Vec::new();
            for (values, zero) in [(assume_load64_zero, true), (assume_load64_nonzero, false)] {
                for address in values {
                    let value = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
                    conditions.push(json!({"address":format!("0x{value:x}"),"width":64,"occurrence":0,"zero":zero}));
                }
            }
            let options = FunctionAnalysisOptions {
                max_blocks,
                resume_from,
                memory_path_conditions: conditions,
                ..Default::default()
            };
            let context = session.analyze_vm_function(entry, &options)?;
            print!("{}", context.local_ir);
            return Ok(());
        }
        Commands::InitVmContext { input, entry, out } => {
            let _integrity = verify_manifest(&root)?;
            let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16)
                .context("entry 必须是十六进制入口地址")?;
            let session = VmSession::open(&root, &input, &out)?;
            let context = session.init_vm_context(entry)?;
            print!("{}", context.local_ir);
            return Ok(());
        }
        Commands::Doctor => {
            let llvm_ir = nereus_llvm_support::smoke_ir()?;
            let integrity = verify_manifest(&root)?;
            let mut worker = Worker::spawn(&worker_path)?;
            let hello = worker.request(json!({"op": "hello"}))?;
            let z3 = std::env::var("NEREUS_Z3").context("NEREUS_Z3 未配置，请先进入项目环境")?;
            json!({
                "ok": true,
                "rust": version("rustc", &["--version"] )?,
                "llvm_config": version("llvm-config", &["--version"] )?,
                "llvm_ir_verified": llvm_ir.contains("define i64 @wrapping_add"),
                "provider_integrity": integrity,
                "z3": version(&z3, &["--version"] )?,
                "worker": hello,
                "implementation_stage": "toolchain-foundation",
                "vm_devirtualization_implemented": false
            })
        }
        Commands::LiftInstruction {
            arch,
            pc,
            bytes,
            out,
        } => {
            let _integrity = verify_manifest(&root)?;
            let architecture = match arch.as_str() {
                "x86" => Architecture::X86,
                "amd64" => Architecture::Amd64,
                _ => bail!("只支持 x86/amd64"),
            };
            let pc_value = u64::from_str_radix(pc.trim_start_matches("0x"), 16)
                .context("pc 必须是十六进制地址")?;
            let bytes = hex::decode(bytes)?;
            let decoded = nereus_x86::decode_one(architecture, pc_value, &bytes)?;
            if decoded.length != bytes.len() {
                bail!("请提供恰好一条指令，iced 长度为 {}", decoded.length);
            }
            fs::create_dir_all(&out)?;
            let out = out.canonicalize()?;
            let mut worker = Worker::spawn(&worker_path)?;
            let remill = worker.request(json!({
                "op": "lift-one", "architecture": arch, "pc": format!("0x{pc_value:x}"),
                "bytes": hex::encode(&bytes), "output_dir": out,
                "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
            }))?;
            if remill["length"].as_u64() != Some(decoded.length as u64) {
                bail!("DECODER_MISMATCH: Remill 与 iced 的长度不同");
            }
            let bitcode = remill["bitcode"]
                .as_str()
                .context("worker 没有返回 bitcode 路径")?;
            let module = nereus_llvm_support::verify_bitcode(Path::new(bitcode))?;
            let result = json!({"ok": true, "iced": decoded, "remill": remill, "llvm": module, "function_recovered": false});
            fs::write(out.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
            result
        }
        Commands::VerifyBitcode { path } => {
            serde_json::to_value(nereus_llvm_support::verify_bitcode(&path)?)?
        }
        Commands::LiftPeBlock {
            input,
            va,
            out,
            max_bytes,
            max_instructions,
        } => {
            let _integrity = verify_manifest(&root)?;
            if max_bytes == 0
                || max_bytes > 16384
                || max_instructions == 0
                || max_instructions > 4096
            {
                bail!("预算要求：1..16384 字节，1..4096 指令");
            }
            let input = input.canonicalize()?;
            let image_bytes = fs::read(&input)?;
            let image_hash = hex::encode(Sha256::digest(&image_bytes));
            let image = nereus_loader::PeImage::parse(&image_bytes)?;
            let va = u64::from_str_radix(va.trim_start_matches("0x"), 16)
                .context("va 必须是十六进制地址")?;
            let mapping = image.map_executable_va(va, image_bytes.len())?;
            let architecture = if image.bitness == 64 {
                Architecture::Amd64
            } else {
                Architecture::X86
            };
            let arch_name = if image.bitness == 64 { "amd64" } else { "x86" };
            let length = max_bytes.min(mapping.available_raw_bytes);
            let window = &image_bytes[mapping.file_offset..mapping.file_offset + length];
            let block = nereus_x86::decode_basic_block(architecture, va, window, max_instructions)?;
            fs::create_dir_all(&out)?;
            let out = out.canonicalize()?;
            let block_bytes = &window[..block.byte_length];
            fs::write(out.join("block.bin"), block_bytes)?;
            let listing = block
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
            fs::write(
                out.join("block.asm"),
                format!(
                    "; image_base={:#x}, rva={:#x}, file_offset={:#x}\n{listing}\n",
                    image.image_base, mapping.rva, mapping.file_offset
                ),
            )?;
            let lengths: Vec<_> = block
                .instructions
                .iter()
                .map(|item| item.instruction.length)
                .collect();
            let mut worker = Worker::spawn(&worker_path)?;
            let remill = worker.request(json!({
                "op": "lift-block", "architecture": arch_name, "pc": format!("0x{va:x}"),
                "bytes": hex::encode(block_bytes), "instruction_lengths": lengths,
                "output_dir": out,
                "semantics_dir": root.join("toolchains/remill-install/share/remill/17/semantics")
            }))?;
            let raw_verified = nereus_llvm_support::verify_bitcode(&out.join("block.raw.bc"))?;
            let function_name = remill["function_name"]
                .as_str()
                .context("worker 未返回块函数名")?;
            let prepared = prepare_block_il(&root, &out, function_name)?;
            let result = json!({
                "ok": true, "input": input, "input_sha256": image_hash,
                "address_policy": "pe-preferred-image-base", "pe": image, "mapping": mapping,
                "boundary_policy": "first control transfer, including call; entry supplied by user",
                "block": block, "remill": remill, "raw_llvm": raw_verified, "prepared": prepared,
                "source_executed": false, "function_recovered": false, "behavior_equivalence_verified": false
            });
            fs::write(out.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
            result
        }
    };
    println!("{}", serde_json::to_string_pretty::<Value>(&result)?);
    Ok(())
}
