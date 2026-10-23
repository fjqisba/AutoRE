// SPDX-License-Identifier: Apache-2.0
//! GUI 与 AI 使用同一个分析引擎；JSONL 通过 stdio 提供，不开放网络端口。
use crate::{Cancellation, Engine, Limits, Result, WorkerPool};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{BufRead, Read, Write},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub address: Option<Value>,
    #[serde(default)]
    pub count: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limits: Limits,
}
pub fn parse_address(value: &Value) -> Result<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    if let Some(s) = value.as_str() {
        return u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
            .map_err(|_| "address string must be hexadecimal".into());
    }
    Err("address must be an integer or a hexadecimal string".into())
}
pub fn execute(engine: &Engine, request: &Request, cancel: &Cancellation) -> Result<Value> {
    cancel.check()?;
    let address = || {
        request
            .address
            .as_ref()
            .ok_or("address is required".into())
            .and_then(parse_address)
    };
    match request.method.as_str() {
        "metadata" | "segments" => Ok(json!(engine.image.metadata())),
        "functions" => {
            let index = engine.symbols(cancel)?;
            let offset = request.offset.unwrap_or(0);
            let count = request.count.unwrap_or(100).clamp(1, 1000);
            Ok(
                json!({"functions":index.functions.iter().skip(offset).take(count).collect::<Vec<_>>(),"total":index.functions.len(),"truncated":index.truncated,"warnings":index.warnings}),
            )
        }
        "read" => {
            let address = address()?;
            let bytes = engine
                .image
                .read_virtual(address, request.count.unwrap_or(256).clamp(1, 65536))?;
            Ok(
                json!({"address":format!("0x{address:x}"),"bytes":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()}),
            )
        }
        "disassemble" => Ok(json!(engine.disassemble(
            address()?,
            request.count.unwrap_or(128),
            cancel
        )?)),
        "analyze" => Ok(json!(engine.analyze(address()?, request.limits, cancel)?)),
        _ => Err(format!(
            "unknown method {}; expected metadata, segments, functions, read, disassemble, analyze",
            request.method
        )),
    }
}
fn write_response(output: &Mutex<std::io::Stdout>, value: Value) {
    if let Ok(mut output) = output.lock() {
        let _ = writeln!(output, "{value}");
        let _ = output.flush();
    }
}
pub fn serve(engine: Arc<Engine>) -> Result<()> {
    let pool = WorkerPool::default();
    let output = Arc::new(Mutex::new(std::io::stdout()));
    let active: Arc<Mutex<HashMap<String, Cancellation>>> = Arc::new(Mutex::new(HashMap::new()));
    let (finished_tx, finished_rx) = crossbeam_channel::unbounded();
    let mut submitted = 0usize;
    let input = std::io::stdin();
    let mut reader = input.lock();
    loop {
        // 长期运行的 agent 会话不能累计所有历史完成通知。
        for _ in finished_rx.try_iter() {
            submitted = submitted.saturating_sub(1);
        }
        // Take 限制单行分配，过长请求直接关闭本地协议会话。
        let mut line = String::new();
        let n = reader
            .by_ref()
            .take(65537)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if n > 65536 {
            return Err("JSONL request exceeds 64 KiB".into());
        }
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_response(&output, json!({"id":null,"error":e.to_string()}));
                continue;
            }
        };
        if request.method == "cancel" {
            let key = request.id.to_string();
            let found = active.lock().unwrap().get(&key).cloned();
            if let Some(token) = found.as_ref() {
                token.cancel();
            }
            write_response(
                &output,
                json!({"id":request.id,"cancel_requested":found.is_some()}),
            );
            continue;
        }
        let key = request.id.to_string();
        let token = Cancellation::default();
        {
            let mut map = active.lock().unwrap();
            if map.contains_key(&key) {
                write_response(
                    &output,
                    json!({"id":request.id,"error":"duplicate in-flight request id"}),
                );
                continue;
            }
            map.insert(key.clone(), token.clone());
        }
        let engine = engine.clone();
        let destination = output.clone();
        let map = active.clone();
        let done = finished_tx.clone();
        let fail_id = request.id.clone();
        let task_key = key.clone();
        let result = pool.submit(move || {
            let response = match execute(&engine, &request, &token) {
                Ok(result) => json!({"id":request.id,"result":result}),
                Err(error) => json!({"id":request.id,"error":error}),
            };
            write_response(&destination, response);
            map.lock().unwrap().remove(&task_key);
            let _ = done.send(());
        });
        if let Err(error) = result {
            active.lock().unwrap().remove(&key);
            write_response(&output, json!({"id":fail_id,"error":error}));
        } else {
            submitted += 1;
        }
    }
    // EOF 仍然等待已接受请求完成，避免管道调用丢结果；每项分析都有预算。
    for _ in 0..submitted {
        finished_rx.recv().map_err(|e| e.to_string())?;
    }
    Ok(())
}
