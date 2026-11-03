// SPDX-License-Identifier: Apache-2.0
#[path = "../tests/support/fixture.rs"]
mod fixture;
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(args.next().ok_or("output path required")?);
    let length = args
        .next()
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(0x3400);
    if length < 0x3400 {
        return Err("fixture must be at least 13312 bytes".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    if length > 16 * 1024 * 1024 {
        #[cfg(windows)]
        {
            let status = std::process::Command::new("fsutil")
                .args(["sparse", "setflag"])
                .arg(&path)
                .stdout(std::process::Stdio::null())
                .status()?;
            if !status.success() {
                return Err("could not mark fixture sparse; refusing huge allocation".into());
            }
        }
    }
    file.set_len(length)?;
    let mut bytes = fixture::fixture();
    // 大文件数据段覆盖整个剩余文件，仍不读取它的内容。
    bytes[152..160].copy_from_slice(&(length - 0x2000).to_le_bytes());
    bytes[160..168].copy_from_slice(&(length - 0x2000 + 4096).to_le_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    println!(
        "{}: {} bytes (synthetic AArch64 ELF)",
        path.display(),
        length
    );
    Ok(())
}
