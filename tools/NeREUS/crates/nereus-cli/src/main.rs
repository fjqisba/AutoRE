use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nereus_core::Architecture;
use nereus_remill::Worker;
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
    };
    println!("{}", serde_json::to_string_pretty::<Value>(&result)?);
    Ok(())
}
