use anyhow::{Context, Result, bail};
use nereus_core::PROTOCOL_VERSION;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

pub struct Worker {
    child: Child,
    input: ChildStdin,
    output: Receiver<std::result::Result<Vec<u8>, String>>,
    next_request: u64,
}

impl Worker {
    pub fn spawn(path: &Path) -> Result<Self> {
        let mut command = Command::new(path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW：不弹出额外终端。
        }
        let mut child = command
            .spawn()
            .context("SEMANTICS_PROVIDER_MISSING: 无法启动 Remill worker")?;
        let input = child.stdin.take().context("worker stdin 缺失")?;
        let stdout = child.stdout.take().context("worker stdout 缺失")?;
        let (sender, output) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                // 多读一个字节用来识别超限；后台读取允许主线程实施响应超时。
                match Read::take(&mut reader, 16 * 1024 * 1024 + 1).read_until(b'\n', &mut bytes) {
                    Ok(0) => break,
                    Ok(length) if length <= 16 * 1024 * 1024 && bytes.last() == Some(&b'\n') => {
                        if sender.send(Ok(bytes)).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        let _ = sender.send(Err("响应超限或未完整分帧".into()));
                        break;
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            child,
            input,
            output,
            next_request: 1,
        })
    }

    pub fn request(&mut self, mut request: Value) -> Result<Value> {
        if !request.is_object() {
            bail!("INVALID_REQUEST: 请求必须是 JSON object");
        }
        request["protocol_version"] = PROTOCOL_VERSION.into();
        let request_id = self.next_request;
        self.next_request += 1;
        request["request_id"] = request_id.into();
        let encoded = serde_json::to_vec(&request)?;
        if encoded.len() + 1 > 16 * 1024 * 1024 {
            bail!("INVALID_REQUEST: 请求超出 16 MiB 帧上限");
        }
        self.input.write_all(&encoded)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        // 完整 VM 路径的逐指令 trace 优化可能长于单块；仍保持显式超时和失败诊断。
        let timeout = if request["op"] == "optimize-local" {
            120
        } else {
            30
        };
        let bytes = match self.output.recv_timeout(Duration::from_secs(timeout)) {
            Ok(Ok(bytes)) => bytes,
            other => {
                let exit_status = self.child.try_wait()?;
                let _ = self.child.kill();
                bail!("WORKER_FAILED: 响应失败或超时: {other:?}; exit_status={exit_status:?}");
            }
        };
        let result: Value = serde_json::from_slice(&bytes)?;
        if result["protocol_version"].as_u64() != Some(u64::from(PROTOCOL_VERSION)) {
            bail!("SEMANTICS_VERSION_MISMATCH: worker 协议版本不匹配");
        }
        if result["request_id"].as_u64() != Some(request_id) {
            bail!("WORKER_FAILED: 响应 request_id 不匹配");
        }
        if result["ok"] != true {
            bail!("worker 请求失败: {result}");
        }
        Ok(result)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
