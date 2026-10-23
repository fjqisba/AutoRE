// SPDX-License-Identifier: Apache-2.0
//! 与 GUI 使用相同索引会话的离线验收入口，不启动服务。
use llmghidra_analysis::{
    index::{store::Store, IndexSession},
    ElfImage,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
fn main() -> Result<(), String> {
    let path = std::env::args().nth(1).ok_or("usage: baseline file.so")?;
    let start = Instant::now();
    let session = IndexSession::new(Arc::new(ElfImage::open(path)?))?;
    session.start();
    let mut first = None;
    loop {
        let p = session.progress();
        if first.is_none() && p.counts.functions > 0 {
            first = Some(start.elapsed().as_secs_f64() * 1000.0);
        }
        if !p.running {
            let store = Store::read(&session.path)?;
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"progress":p,"first_functions_ms":first,"jni":store.functions("JNI_OnLoad",None,10)?,"jni_incoming":store.xrefs(0x383f84,0x383f85,true,None,10)?,"strings":store.strings("React",None,5)?,"functions":store.functions("",None,5)?})).map_err(|e|e.to_string())?);
            if !p.complete && !p.phase.starts_with("Baseline partial") {
                return Err(p.phase);
            }
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            session.cancel();
            return Err("Index exceeded 120-second acceptance budget".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
