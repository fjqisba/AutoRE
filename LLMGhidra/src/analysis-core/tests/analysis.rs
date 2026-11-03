// SPDX-License-Identifier: Apache-2.0
mod support {
    pub mod fixture;
}
use llmghidra_analysis::{protocol, Cancellation, ElfImage, Engine, Limits};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../temp_data/egui-workbench/tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "fixture-{}-{}.elf",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[test]
fn opening_reads_headers_not_segments() {
    let f = Fixture::new(&support::fixture::fixture());
    let image = ElfImage::open(&f.0).unwrap();
    assert_eq!(image.bytes_read(), 192);
    assert_eq!(image.machine, 183);
    assert_eq!(image.segments.len(), 2);
    assert_eq!(image.file_offset(0x401000), Some(0x1000));
    assert_eq!(image.file_offset(0x403500), None);
    assert_eq!(image.read_virtual(0x403500, 16).unwrap(), vec![0; 16]);
    assert_eq!(image.bytes_read(), 192);
    assert!(image.read_virtual(0x400000, 8).is_err());
    assert!(image.read_file(u64::MAX, 8).is_err());
}
#[test]
fn recursive_analysis_follows_branches_not_callees() {
    let f = Fixture::new(&support::fixture::fixture());
    let engine = Engine::new(ElfImage::open(&f.0).unwrap());
    let result = engine
        .analyze(0x401000, Limits::default(), &Cancellation::default())
        .unwrap();
    assert!(!result.partial, "{:?}", result.reasons);
    assert_eq!(result.instructions.len(), 7);
    assert_eq!(result.blocks.len(), 3);
    assert_eq!(result.functions[0].address, 0x401040);
    assert!(!result.instructions.iter().any(|i| i.address == 0x401040));
    assert!(result
        .edges
        .iter()
        .any(|e| e.kind == "taken" && e.to == Some(0x401014)));
    let before = engine.image.bytes_read();
    engine
        .disassemble(0x401000, 16, &Cancellation::default())
        .unwrap();
    assert_eq!(engine.image.bytes_read(), before);
}
#[test]
fn symbols_are_lazy_cached_and_shared() {
    let f = Fixture::new(&support::fixture::fixture());
    let engine = Engine::new(ElfImage::open(&f.0).unwrap());
    let first = engine.symbols(&Cancellation::default()).unwrap();
    assert!(first
        .functions
        .iter()
        .any(|f| f.name == "helper" && f.address == 0x401040));
    let before = engine.image.bytes_read();
    let second = engine.symbols(&Cancellation::default()).unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &second));
    assert_eq!(before, engine.image.bytes_read());
}
#[test]
fn cancellation_and_budget_are_explicit() {
    let f = Fixture::new(&support::fixture::fixture());
    let engine = Engine::new(ElfImage::open(&f.0).unwrap());
    let limits = Limits {
        instructions: 2,
        ..Default::default()
    };
    let result = engine
        .analyze(0x401000, limits, &Cancellation::default())
        .unwrap();
    assert!(result.partial);
    assert_eq!(result.instructions.len(), 2);
    let token = Cancellation::default();
    token.cancel();
    assert!(engine.analyze(0x401000, Limits::default(), &token).is_err());
    assert!(engine
        .disassemble(0x402000, 4, &Cancellation::default())
        .is_err());
}
#[test]
fn sectionless_file_still_opens_and_decodes() {
    let mut bytes = support::fixture::fixture();
    bytes[40..48].fill(0);
    bytes[60..62].fill(0);
    let f = Fixture::new(&bytes);
    let engine = Engine::new(ElfImage::open(&f.0).unwrap());
    assert!(!engine
        .symbols(&Cancellation::default())
        .unwrap()
        .warnings
        .is_empty());
    assert_eq!(
        engine
            .disassemble(0x401000, 1, &Cancellation::default())
            .unwrap()[0]
            .mnemonic,
        "mov"
    );
}
#[test]
fn malformed_headers_are_rejected_without_large_allocations() {
    let original = support::fixture::fixture();
    for n in [0, 4, 15, 51, 63, 119, 175] {
        let f = Fixture::new(&original[..n]);
        assert!(ElfImage::open(&f.0).is_err());
    }
    let mut bytes = original.clone();
    bytes[96..104].copy_from_slice(&u64::MAX.to_le_bytes());
    let f = Fixture::new(&bytes);
    assert!(ElfImage::open(&f.0).is_err());
    let mut bytes = original;
    bytes[80..88].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
    let f = Fixture::new(&bytes);
    assert!(ElfImage::open(&f.0).is_err());
}
#[test]
fn elf32_big_endian_metadata_and_bss() {
    let mut b = vec![0u8; 128];
    b[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
    for (at, value, size) in [
        (16, 2u32, 2),
        (18, 40, 2),
        (20, 1, 4),
        (24, 0x8000, 4),
        (28, 52, 4),
        (40, 52, 2),
        (42, 32, 2),
        (44, 1, 2),
        (52, 1, 4),
        (56, 84, 4),
        (60, 0x8000, 4),
        (68, 4, 4),
        (72, 16, 4),
        (76, 5, 4),
        (80, 1, 4),
    ] {
        b[at..at + size].copy_from_slice(&value.to_be_bytes()[4 - size..]);
    }
    b[84..88].copy_from_slice(&[1, 2, 3, 4]);
    let f = Fixture::new(&b);
    let image = ElfImage::open(&f.0).unwrap();
    assert_eq!(image.bits, 32);
    assert!(!image.little);
    assert_eq!(
        image.read_virtual(0x8000, 8).unwrap(),
        vec![1, 2, 3, 4, 0, 0, 0, 0]
    );
}
#[test]
fn protocol_uses_same_engine_and_paginates() {
    let f = Fixture::new(&support::fixture::fixture());
    let engine = Engine::new(ElfImage::open(&f.0).unwrap());
    let request =
        serde_json::from_str(r#"{"id":"a","method":"functions","count":1,"offset":1}"#).unwrap();
    let result = protocol::execute(&engine, &request, &Cancellation::default()).unwrap();
    assert_eq!(result["functions"].as_array().unwrap().len(), 1);
    assert_eq!(
        protocol::parse_address(&serde_json::json!("0x401000")).unwrap(),
        0x401000
    );
}
