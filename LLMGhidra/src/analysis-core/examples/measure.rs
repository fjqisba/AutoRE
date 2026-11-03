// SPDX-License-Identifier: Apache-2.0
use llmghidra_analysis::{Cancellation, ElfImage, Engine, Limits};
use std::time::Instant;
fn main() -> Result<(), String> {
    let path = std::env::args().nth(1).ok_or("ELF path required")?;
    let start = Instant::now();
    let image = ElfImage::open(&path)?;
    let open_ms = start.elapsed().as_secs_f64() * 1000.0;
    let open_reads = image.bytes_read();
    let length = image.length;
    let address = image.initial_address();
    let engine = Engine::new(image);
    let start = Instant::now();
    let listing = engine.disassemble(address, 256, &Cancellation::default())?;
    let page_ms = start.elapsed().as_secs_f64() * 1000.0;
    let analysis = engine.analyze(address, Limits::default(), &Cancellation::default())?;
    let start = Instant::now();
    let symbols = engine.symbols(&Cancellation::default())?;
    let symbols_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({"path":path,"file_bytes":length,"header_open_ms":open_ms,"header_bytes_read":open_reads,"page_ms":page_ms,"page_instructions":listing.len(),"analysis_ms":analysis.elapsed_ms,"analysis_instructions":analysis.instructions.len(),"analysis_blocks":analysis.blocks.len(),"analysis_partial":analysis.partial,"symbols_ms":symbols_ms,"function_seeds":symbols.functions.len(),"total_bytes_read":engine.image.bytes_read()})
    );
    Ok(())
}
